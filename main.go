package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/turn/v4"
	qrcode "github.com/skip2/go-qrcode"
)

// ServerConfig holds the CLI / Environment configuration
type Config struct {
	HTTPPort       int
	TURNPort       int
	PublicIP       string
	DuckDomain     string
	DuckToken      string
	EnableUPnP     bool
	Realm          string
	Username       string
	Password       string
	AuthSecret     string
	MinRelayPort   int
	MaxRelayPort   int
	EnableTLS      bool
	TLSCertFile    string
	TLSKeyFile     string
	AppPublicURL   string
	mu             sync.RWMutex
}

func (c *Config) SetPublicIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PublicIP = ip
}

func (c *Config) GetPublicIP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.PublicIP
}

// PeerMessage represents messages exchanged over PeerJS signaling
type PeerMessage struct {
	Type    string          `json:"type"`
	Src     string          `json:"src,omitempty"`
	Dst     string          `json:"dst,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Msg     string          `json:"msg,omitempty"`
}

// Client represents a connected PeerJS client
type Client struct {
	ID       string
	Token    string
	Conn     *websocket.Conn
	mu       sync.Mutex
	LastSeen time.Time
}

func (c *Client) SendJSON(v interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.Conn.WriteJSON(v)
}

// SignalingServer manages PeerJS WebSocket and HTTP connections
type SignalingServer struct {
	clients  map[string]*Client
	mu       sync.RWMutex
	upgrader websocket.Upgrader
	cfg      *Config
}

func NewSignalingServer(cfg *Config) *SignalingServer {
	return &SignalingServer{
		clients: make(map[string]*Client),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for P2P web clients
			},
			ReadBufferSize:  1024 * 32,
			WriteBufferSize: 1024 * 32,
		},
		cfg: cfg,
	}
}

func (s *SignalingServer) AddClient(id, token string, conn *websocket.Conn) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If client exists, close old connection
	if old, exists := s.clients[id]; exists {
		old.mu.Lock()
		_ = old.Conn.Close()
		old.mu.Unlock()
	}

	client := &Client{
		ID:       id,
		Token:    token,
		Conn:     conn,
		LastSeen: time.Now(),
	}
	s.clients[id] = client
	log.Printf("[PeerJS] Registered client ID: %s (total clients: %d)", id, len(s.clients))
	return client
}

func (s *SignalingServer) RemoveClient(id, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, exists := s.clients[id]; exists {
		if token == "" || client.Token == token {
			delete(s.clients, id)
			log.Printf("[PeerJS] Unregistered client ID: %s (remaining: %d)", id, len(s.clients))
		}
	}
}

func (s *SignalingServer) GetClient(id string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[id]
}

func (s *SignalingServer) ClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// HandleWebSocket handles incoming WebSocket connections for PeerJS
func (s *SignalingServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[PeerJS WS] Upgrade error: %v", err)
		return
	}

	query := r.URL.Query()
	id := query.Get("id")
	token := query.Get("token")

	if id == "" {
		id = fmt.Sprintf("%08d", rand.Intn(100000000))
	}

	client := s.AddClient(id, token, conn)

	// Send OPEN message
	if err := client.SendJSON(PeerMessage{Type: "OPEN"}); err != nil {
		log.Printf("[PeerJS] Error sending OPEN to %s: %v", id, err)
		s.RemoveClient(id, token)
		conn.Close()
		return
	}

	// Message processing loop
	go func() {
		defer func() {
			s.RemoveClient(id, token)
			conn.Close()
		}()

		for {
			var msg PeerMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("[PeerJS WS] Read error from %s: %v", id, err)
				}
				break
			}

			client.LastSeen = time.Now()

			switch msg.Type {
			case "HEARTBEAT":
				_ = client.SendJSON(PeerMessage{Type: "HEARTBEAT"})

			case "OFFER", "ANSWER", "CANDIDATE", "LEAVE":
				if msg.Dst == "" {
					continue
				}
				target := s.GetClient(msg.Dst)
				if target != nil {
					msg.Src = id
					if err := target.SendJSON(msg); err != nil {
						log.Printf("[PeerJS] Failed to forward %s from %s to %s: %v", msg.Type, id, msg.Dst, err)
					}
				} else {
					log.Printf("[PeerJS] Destination %s not found for message from %s", msg.Dst, id)
					_ = client.SendJSON(PeerMessage{
						Type: "ERROR",
						Msg:  fmt.Sprintf("Could not connect to peer %s", msg.Dst),
					})
				}

			default:
				log.Printf("[PeerJS] Unknown message type '%s' from %s", msg.Type, id)
			}
		}
	}()
}

// ClientConfigJSON returns the configuration object for Pingo app
type ClientConfigJSON struct {
	Version   int `json:"version"`
	Signaling struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Path   string `json:"path"`
		Secure bool   `json:"secure"`
	} `json:"signaling"`
	Turn struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"turn"`
}

func getLocalOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}
	return "127.0.0.1"
}

func fetchPublicIP() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		ipBytes, err := io.ReadAll(resp.Body)
		if err == nil && len(ipBytes) > 0 {
			ipStr := strings.TrimSpace(string(ipBytes))
			if net.ParseIP(ipStr) != nil {
				return ipStr
			}
		}
	}
	return getLocalOutboundIP()
}

func generatePairConfig(cfg *Config) (ClientConfigJSON, string, string) {
	publicHost := cfg.GetPublicIP()
	clientConfig := ClientConfigJSON{
		Version: 1,
	}
	clientConfig.Signaling.Host = publicHost
	clientConfig.Signaling.Port = cfg.HTTPPort
	clientConfig.Signaling.Path = "/"
	clientConfig.Signaling.Secure = cfg.EnableTLS

	clientConfig.Turn.URLs = []string{
		fmt.Sprintf("stun:%s:%d", publicHost, cfg.TURNPort),
		fmt.Sprintf("turn:%s:%d?transport=udp", publicHost, cfg.TURNPort),
	}
	clientConfig.Turn.Username = cfg.Username
	clientConfig.Turn.Credential = cfg.Password

	configJSONBytes, _ := json.MarshalIndent(clientConfig, "", "  ")
	configBase64 := base64.URLEncoding.EncodeToString([]byte(configJSONBytes))
	pairURL := fmt.Sprintf("%s/?serverConfig=%s", cfg.AppPublicURL, configBase64)

	return clientConfig, string(configJSONBytes), pairURL
}

func main() {
	httpPort := flag.Int("port", 9000, "HTTP and WebSocket signaling port")
	turnPort := flag.Int("turn-port", 3478, "STUN/TURN UDP listening port")
	publicIPFlag := flag.String("public-ip", "", "Public IP or domain of this server")
	duckDomain := flag.String("duck-domain", "", "DuckDNS Subdomain (e.g. 'mi-nodo')")
	duckToken := flag.String("duck-token", "", "DuckDNS API Token")
	enableUPnP := flag.Bool("upnp", true, "Enable UPnP router port mapping and diagnostics")
	noUPnP := flag.Bool("no-upnp", false, "Disable UPnP port mapping")
	runWizard := flag.Bool("wizard", false, "Launch interactive CLI Setup Wizard before starting")
	realm := flag.String("realm", "pingo", "TURN realm")
	username := flag.String("user", "pingo", "TURN default username")
	password := flag.String("password", "pingosecret", "TURN default password")
	authSecret := flag.String("secret", "pingo-static-auth-secret", "TURN static auth secret")
	minPort := flag.Int("min-port", 49152, "Minimum UDP relay port")
	maxPort := flag.Int("max-port", 65535, "Maximum UDP relay port")
	enableTLS := flag.Bool("tls", false, "Enable TLS for HTTPS/WSS")
	tlsCert := flag.String("tls-cert", "cert.pem", "TLS Certificate file")
	tlsKey := flag.String("tls-key", "key.pem", "TLS Private Key file")
	appURL := flag.String("app-url", "https://pingo.accreativos.com", "Base URL of Pingo app")

	flag.Parse()

	// Environment variable overrides
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*httpPort = p
		}
	}
	if envTurn := os.Getenv("TURN_PORT"); envTurn != "" {
		if p, err := strconv.Atoi(envTurn); err == nil {
			*turnPort = p
		}
	}
	if envIP := os.Getenv("PUBLIC_IP"); envIP != "" {
		*publicIPFlag = envIP
	}
	if envDuckDom := os.Getenv("DUCKDNS_DOMAIN"); envDuckDom != "" {
		*duckDomain = envDuckDom
	}
	if envDuckTok := os.Getenv("DUCKDNS_TOKEN"); envDuckTok != "" {
		*duckToken = envDuckTok
	}
	if envUPnP := os.Getenv("ENABLE_UPNP"); envUPnP == "false" || envUPnP == "0" {
		*enableUPnP = false
	}
	if *noUPnP {
		*enableUPnP = false
	}

	cfg := &Config{
		HTTPPort:     *httpPort,
		TURNPort:     *turnPort,
		PublicIP:     *publicIPFlag,
		DuckDomain:   *duckDomain,
		DuckToken:    *duckToken,
		EnableUPnP:   *enableUPnP,
		Realm:        *realm,
		Username:     *username,
		Password:     *password,
		AuthSecret:   *authSecret,
		MinRelayPort: *minPort,
		MaxRelayPort: *maxPort,
		EnableTLS:    *enableTLS,
		TLSCertFile:  *tlsCert,
		TLSKeyFile:   *tlsKey,
		AppPublicURL: *appURL,
	}

	// Interactive Wizard if requested
	if *runWizard {
		RunCLIWizard(cfg)
	}

	localIP := getLocalOutboundIP()
	detectedPublicIP := fetchPublicIP()

	if cfg.PublicIP == "" {
		if cfg.DuckDomain != "" {
			cfg.PublicIP = formatFullDomain(cfg.DuckDomain)
		} else {
			cfg.PublicIP = detectedPublicIP
		}
	}

	log.Printf("[Init] Local Network IP: %s", localIP)
	log.Printf("[Init] Public WAN IP (Internet): %s", detectedPublicIP)
	log.Printf("[Init] Configured Host/Domain: %s", cfg.PublicIP)

	// Initialize UPnP Manager
	upnpMgr := NewUPnPManager(cfg.TURNPort, cfg.HTTPPort, localIP, detectedPublicIP)
	if cfg.EnableUPnP {
		log.Println("[UPnP] Escaneando red local en busca de router IGD...")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		report := upnpMgr.DiscoverAndMap(ctx)
		cancel()
		log.Printf("[UPnP] Resultado: %s", report.Message)
	} else {
		log.Println("[UPnP] Desactivado por configuración.")
	}

	// Initialize DuckDNS Manager
	duckMgr := NewDuckDNSManager(cfg.DuckDomain, cfg.DuckToken, func(fullDomain, currentIP string) {
		cfg.SetPublicIP(fullDomain)
		log.Printf("[DuckDNS Callback] Host actualizado a: %s", fullDomain)
	})
	if cfg.DuckDomain != "" && cfg.DuckToken != "" {
		log.Printf("[DuckDNS] Activando sincronización periódica para '%s'...", formatFullDomain(cfg.DuckDomain))
		duckMgr.StartBackgroundSync()
	}

	// 1. Initialize Pion TURN / STUN Server
	turnIP := net.ParseIP(detectedPublicIP)
	if turnIP == nil {
		turnIP = net.ParseIP("127.0.0.1")
	}

	turnUDPListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", cfg.TURNPort))
	if err != nil {
		log.Fatalf("[TURN] Failed to listen on UDP port %d: %v", cfg.TURNPort, err)
	}
	defer turnUDPListener.Close()

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm,
		AuthHandler: func(u string, r string, srcAddr net.Addr) ([]byte, bool) {
			if u == cfg.Username {
				return turn.GenerateAuthKey(u, r, cfg.Password), true
			}
			if cfg.AuthSecret != "" {
				parts := strings.Split(u, ":")
				if len(parts) >= 2 {
					mac := hmac.New(sha1.New, []byte(cfg.AuthSecret))
					mac.Write([]byte(u))
					expectedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))
					return turn.GenerateAuthKey(u, r, expectedPassword), true
				}
				return turn.GenerateAuthKey(u, r, cfg.AuthSecret), true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: turnUDPListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: turnIP,
					Address:      "0.0.0.0",
					MinPort:      uint16(cfg.MinRelayPort),
					MaxPort:      uint16(cfg.MaxRelayPort),
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("[TURN] Failed to create TURN server: %v", err)
	}
	defer turnServer.Close()
	log.Printf("[TURN] Relay UDP listo en 0.0.0.0:%d (Externo: %s:%d)", cfg.TURNPort, cfg.PublicIP, cfg.TURNPort)

	// 2. Initialize PeerJS Signaling Server
	sigServer := NewSignalingServer(cfg)
	mux := http.NewServeMux()

	handleWS := func(w http.ResponseWriter, r *http.Request) {
		sigServer.HandleWebSocket(w, r)
	}

	// PeerJS endpoints
	mux.HandleFunc("/peerjs", handleWS)
	mux.HandleFunc("/peerjs/peerjs", handleWS)
	mux.HandleFunc("/peerjs/id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%08d", rand.Intn(100000000))
	})
	mux.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%08d", rand.Intn(100000000))
	})

	// API Endpoints
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		clientCfg, _, pairURL := generatePairConfig(cfg)

		respData := map[string]interface{}{
			"status":        "ok",
			"clients_count": sigServer.ClientCount(),
			"public_host":   cfg.GetPublicIP(),
			"http_port":     cfg.HTTPPort,
			"turn_port":     cfg.TURNPort,
			"tls":           cfg.EnableTLS,
			"pair_url":      pairURL,
			"config":        clientCfg,
			"upnp":          upnpMgr.GetReport(),
			"duckdns":       duckMgr.GetStatus(),
		}
		_ = json.NewEncoder(w).Encode(respData)
	})

	mux.HandleFunc("/api/duckdns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Domain string `json:"domain"`
			Token  string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		ok, msg, err := duckMgr.SetCredentials(payload.Domain, payload.Token)
		if ok {
			cfg.DuckDomain = payload.Domain
			cfg.DuckToken = payload.Token
			cfg.SetPublicIP(formatFullDomain(payload.Domain))
			duckMgr.StartBackgroundSync()
		}

		status := duckMgr.GetStatus()
		_, _, pairURL := generatePairConfig(cfg)

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     ok,
			"message":     msg,
			"error":       fmt.Sprintf("%v", err),
			"duckdns":     status,
			"public_host": cfg.GetPublicIP(),
			"pair_url":    pairURL,
		})
	})

	mux.HandleFunc("/api/upnp/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		report := upnpMgr.DiscoverAndMap(ctx)
		cancel()

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": report.Active,
			"upnp":    report,
		})
	})

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		clientConfig, _, _ := generatePairConfig(cfg)
		_ = json.NewEncoder(w).Encode(clientConfig)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","clients":%d,"turn":"active"}`+"\n", sigServer.ClientCount())
	})

	// Dashboard & Fallback
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if strings.HasSuffix(path, "/peerjs") {
			handleWS(w, r)
			return
		}
		if strings.HasSuffix(path, "/id") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "%08d", rand.Intn(100000000))
			return
		}

		if path == "" || path == "/" {
			renderDashboard(w, r, cfg, sigServer, upnpMgr, duckMgr)
			return
		}

		http.NotFound(w, r)
	})

	_, configJSON, pairURL := generatePairConfig(cfg)
	printBanner(cfg, pairURL, configJSON, upnpMgr.GetReport(), duckMgr.GetStatus())

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", cfg.HTTPPort),
		Handler: mux,
	}

	go func() {
		proto := "HTTP"
		if cfg.EnableTLS {
			proto = "HTTPS"
			log.Printf("[Signaling] Iniciando servidor %s/WSS en 0.0.0.0:%d...", proto, cfg.HTTPPort)
			if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Signaling] Error HTTPS: %v", err)
			}
		} else {
			log.Printf("[Signaling] Iniciando servidor %s/WS en 0.0.0.0:%d...", proto, cfg.HTTPPort)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Signaling] Error HTTP: %v", err)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[Server] Apagando el servidor con seguridad...")
	duckMgr.Stop()
	_ = httpServer.Close()
	_ = turnServer.Close()
	log.Println("[Server] Detenido.")
}

func printBanner(cfg *Config, pairURL, configJSON string, upnp *UPnPReport, duck DuckDNSStatus) {
	fmt.Println("==================================================================")
	fmt.Println("  🌐 PINGO STANDALONE SERVER (PeerJS Signaling + Pion TURN/STUN)   ")
	fmt.Println("==================================================================")
	fmt.Printf(" • Host Público       : %s\n", cfg.GetPublicIP())
	fmt.Printf(" • Señalización (WS)  : http%s://%s:%d\n", map[bool]string{true: "s", false: ""}[cfg.EnableTLS], cfg.GetPublicIP(), cfg.HTTPPort)
	fmt.Printf(" • Servidor TURN/STUN : turn:%s:%d (UDP)\n", cfg.GetPublicIP(), cfg.TURNPort)
	fmt.Printf(" • Credenciales TURN  : user='%s', password='%s'\n", cfg.Username, cfg.Password)
	fmt.Printf(" • Panel Web / Wizard : http%s://%s:%d/\n", map[bool]string{true: "s", false: ""}[cfg.EnableTLS], cfg.GetPublicIP(), cfg.HTTPPort)

	// UPnP Status
	if upnp != nil && upnp.Active {
		fmt.Printf(" • UPnP Router        : ✅ Activo (%s)\n", strings.Join(upnp.MappedPorts, ", "))
		if upnp.HasCGNAT {
			fmt.Printf(" • Diagnóstico NAT    : ⚠️ CGNAT Detectado (IP Router: %s != WAN)\n", upnp.RouterExternalIP)
		} else {
			fmt.Printf(" • Diagnóstico NAT    : ✅ Sin CGNAT (IP Pública Directa: %s)\n", upnp.RouterExternalIP)
		}
	} else {
		fmt.Println(" • UPnP Router        : ⚠️ No detectado (requiere apertura manual o túnel)")
	}

	// DuckDNS Status
	if duck.Enabled {
		fmt.Printf(" • DuckDNS DDNS       : ✅ %s (Sincronización activa cada 10 min)\n", duck.FullDomain)
	} else {
		fmt.Println(" • DuckDNS DDNS       : ℹ️ No configurado (usando IP directa)")
	}

	fmt.Println("------------------------------------------------------------------")
	fmt.Println(" 📲 VINCULACIÓN INSTANTÁNEA CON PINGO (Escanear QR o Abrir Enlace):")
	fmt.Printf(" %s\n\n", pairURL)

	qr, err := qrcode.New(pairURL, qrcode.Medium)
	if err == nil {
		fmt.Println(qr.ToSmallString(false))
	}
	fmt.Println("------------------------------------------------------------------")
	fmt.Println(" 📄 Configuración JSON para Pingo (Ajustes > Servidores > Importar):")
	fmt.Println(configJSON)
	fmt.Println("==================================================================")
}

func renderDashboard(w http.ResponseWriter, r *http.Request, cfg *Config, sigServer *SignalingServer, upnpMgr *UPnPManager, duckMgr *DuckDNSManager) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, configJSONBytes, pairURL := generatePairConfig(cfg)
	upnpReport := upnpMgr.GetReport()
	duckStatus := duckMgr.GetStatus()

	qrPNG, _ := qrcode.Encode(pairURL, qrcode.Medium, 256)
	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	upnpBadgeClass := "badge-error"
	upnpBadgeText := "UPnP No Detectado"
	if upnpReport.Active {
		if upnpReport.HasCGNAT {
			upnpBadgeClass = "badge-warning"
			upnpBadgeText = "UPnP Activo &bull; CGNAT Detectado"
		} else {
			upnpBadgeClass = "badge-success"
			upnpBadgeText = "UPnP Activo &bull; Puertos Mapeados"
		}
	}

	duckBadgeClass := "badge-muted"
	duckBadgeText := "DuckDNS Inactivo"
	if duckStatus.Enabled {
		if duckStatus.LastSuccess {
			duckBadgeClass = "badge-success"
			duckBadgeText = "DuckDNS Sincronizado"
		} else {
			duckBadgeClass = "badge-warning"
			duckBadgeText = "DuckDNS Error"
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pingo Node - Panel de Control y Diagnóstico</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card-bg: #151e2e;
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --border: #243044;
            --accent: #06b6d4;
        }
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 820px;
            width: 100%%;
        }
        .header {
            text-align: center;
            margin-bottom: 24px;
        }
        .header h1 {
            margin: 0 0 8px 0;
            font-size: 1.8rem;
            letter-spacing: -0.5px;
        }
        .badges-row {
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px;
        }
        .badge {
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .badge-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-error { background: rgba(239, 68, 68, 0.15); color: var(--error); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-muted { background: rgba(148, 163, 184, 0.1); color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.2); }
        .dot { width: 8px; height: 8px; border-radius: 50%%; display: inline-block; background: currentColor; }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 16px -4px rgba(0,0,0,0.3);
        }
        .card h3 {
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 1.15rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .qr-section {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 16px;
        }
        .qr-box {
            background: white;
            padding: 12px;
            border-radius: 10px;
            display: inline-block;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .qr-box img { display: block; border-radius: 4px; }
        
        .btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
        .btn-secondary {
            background: rgba(255,255,255,0.08);
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.15); }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 12px;
            align-items: end;
            margin-top: 12px;
        }
        @media (max-width: 600px) {
            .form-row { grid-template-columns: 1fr; }
        }
        .form-group label {
            display: block;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 500;
        }
        .form-control {
            width: 100%%;
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 9px 12px;
            color: var(--text);
            font-size: 0.9rem;
        }
        .form-control:focus { outline: none; border-color: var(--primary); }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        .stat {
            background: rgba(255,255,255,0.02);
            padding: 12px 14px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-val {
            font-size: 1.1rem;
            font-weight: 700;
            margin-top: 4px;
            color: #e2e8f0;
        }
        pre {
            background: #090d16;
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            color: #38bdf8;
            font-size: 0.82rem;
            margin-top: 8px;
        }
        .alert {
            padding: 12px;
            border-radius: 8px;
            font-size: 0.88rem;
            margin-top: 12px;
            line-height: 1.4;
        }
        .alert-info { background: rgba(6, 182, 212, 0.12); border: 1px solid rgba(6, 182, 212, 0.25); color: #67e8f9; }
        .alert-warning { background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.25); color: #fcd34d; }
        .alert-success { background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.25); color: #6ee7b7; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📡 Nodo Privado Pingo</h1>
            <div class="badges-row">
                <div class="badge badge-success"><span class="dot"></span> Señalización & Relé Activos</div>
                <div class="badge %s" id="upnp-badge"><span class="dot"></span> %s</div>
                <div class="badge %s" id="duck-badge"><span class="dot"></span> %s</div>
            </div>
        </div>

        <!-- QR & Pairing Card -->
        <div class="card qr-section">
            <h2 style="margin:0;">📲 Vinculación Rápida con la App Pingo</h2>
            <p style="color: var(--text-muted); margin: 0; font-size: 0.95rem;">Escanea el QR con la cámara de tu móvil o abre el enlace en tu navegador:</p>
            <div class="qr-box">
                <img id="qr-img" src="data:image/png;base64,%s" alt="QR de Vinculación" width="220" height="220">
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; justify-content:center;">
                <a id="pair-btn" href="%s" target="_blank" class="btn">🚀 Abrir Pingo con este Servidor</a>
                <button onclick="copyPairURL()" class="btn btn-secondary">📋 Copiar Enlace</button>
            </div>
        </div>

        <!-- DuckDNS Wizard Card -->
        <div class="card">
            <h3>
                <span>🦆 Asistente DuckDNS (DNS Dinámico)</span>
                <span style="font-size:0.8rem; font-weight:normal; color:var(--text-muted);">Gratuito en <a href="https://www.duckdns.org" target="_blank" style="color:var(--accent);">duckdns.org</a></span>
            </h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0;">Permite que tu nodo conserve un dominio fijo (ej. <code>tunombre.duckdns.org</code>) aunque tu proveedor de internet cambie tu IP pública.</p>
            <div class="form-row">
                <div class="form-group">
                    <label>Subdominio DuckDNS</label>
                    <input type="text" id="duck-domain-input" class="form-control" placeholder="ej. mi-nodo-pingo" value="%s">
                </div>
                <div class="form-group">
                    <label>Token Privado</label>
                    <input type="password" id="duck-token-input" class="form-control" placeholder="xxxxxxxx-xxxx-xxxx-xxxx" value="%s">
                </div>
                <div class="form-group">
                    <button id="save-duck-btn" onclick="saveDuckDNS()" class="btn">💾 Probar y Guardar</button>
                </div>
            </div>
            <div id="duck-alert" class="alert %s" style="display:%s;">%s</div>
        </div>

        <!-- UPnP & CGNAT Diagnostics Card -->
        <div class="card">
            <h3>
                <span>🔍 Diagnóstico de Red & UPnP</span>
                <button onclick="reScanUPnP()" id="scan-upnp-btn" class="btn btn-secondary" style="font-size:0.8rem; padding:6px 12px;">🔄 Re-escanear Router</button>
            </h3>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Estado UPnP Router</div>
                    <div class="stat-val" id="stat-upnp">%s</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Diagnóstico NAT / CGNAT</div>
                    <div class="stat-val" id="stat-cgnat">%s</div>
                </div>
                <div class="stat">
                    <div class="stat-label">IP Router / WAN</div>
                    <div class="stat-val" id="stat-router-ip">%s</div>
                </div>
                <div class="stat">
                    <div class="stat-label">IP Pública Detectada</div>
                    <div class="stat-val" id="stat-public-ip">%s</div>
                </div>
            </div>
            <div id="upnp-msg-alert" class="alert %s">%s</div>
        </div>

        <!-- Server Statistics -->
        <div class="card">
            <h3>📊 Métricas del Servidor</h3>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Clientes Conectados</div>
                    <div class="stat-val">%d</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Host Configurado</div>
                    <div class="stat-val" id="stat-host">%s</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Puerto Señalización (WS)</div>
                    <div class="stat-val">%d</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Puerto TURN/STUN (UDP)</div>
                    <div class="stat-val">%d</div>
                </div>
            </div>
        </div>

        <!-- JSON Configuration -->
        <div class="card">
            <h3>⚙️ Configuración JSON para Pingo</h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0;">Para importar manualmente en Pingo (<i>Ajustes &rarr; Servidores &rarr; Importar JSON</i>):</p>
            <pre id="json-preview">%s</pre>
        </div>
    </div>

    <script>
        let currentPairURL = "%s";

        function copyPairURL() {
            navigator.clipboard.writeText(currentPairURL).then(() => {
                alert("¡Enlace de vinculación copiado al portapapeles!");
            });
        }

        async function saveDuckDNS() {
            const domain = document.getElementById("duck-domain-input").value.trim();
            const token = document.getElementById("duck-token-input").value.trim();
            const btn = document.getElementById("save-duck-btn");
            const alertBox = document.getElementById("duck-alert");

            if (!domain || !token) {
                alert("Por favor introduce el subdominio y el token de DuckDNS.");
                return;
            }

            btn.disabled = true;
            btn.innerText = "⏳ Verificando...";

            try {
                const res = await fetch("/api/duckdns", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, token })
                });
                const data = await res.json();

                alertBox.style.display = "block";
                if (data.success) {
                    alertBox.className = "alert alert-success";
                    alertBox.innerText = "✅ " + data.message;
                    if (data.pair_url) {
                        currentPairURL = data.pair_url;
                        document.getElementById("pair-btn").href = data.pair_url;
                        document.getElementById("stat-host").innerText = data.public_host;
                    }
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    alertBox.className = "alert alert-warning";
                    alertBox.innerText = "⚠️ " + data.message;
                }
            } catch (err) {
                alertBox.style.display = "block";
                alertBox.className = "alert alert-warning";
                alertBox.innerText = "Error contactando con el servidor: " + err.message;
            } finally {
                btn.disabled = false;
                btn.innerText = "💾 Probar y Guardar";
            }
        }

        async function reScanUPnP() {
            const btn = document.getElementById("scan-upnp-btn");
            btn.disabled = true;
            btn.innerText = "⏳ Escaneando...";

            try {
                const res = await fetch("/api/upnp/scan", { method: "POST" });
                const data = await res.json();
                if (data.upnp) {
                    const alertBox = document.getElementById("upnp-msg-alert");
                    alertBox.innerText = data.upnp.message;
                    alertBox.className = data.upnp.has_cgnat ? "alert alert-warning" : (data.upnp.active ? "alert alert-success" : "alert alert-info");
                    document.getElementById("stat-upnp").innerText = data.upnp.active ? "Activo" : "No detectado";
                    document.getElementById("stat-cgnat").innerText = data.upnp.has_cgnat ? "⚠️ CGNAT" : "✅ Directa";
                    document.getElementById("stat-router-ip").innerText = data.upnp.router_external_ip || "-";
                }
            } catch (e) {
                alert("Error al re-escanear UPnP: " + e.message);
            } finally {
                btn.disabled = false;
                btn.innerText = "🔄 Re-escanear Router";
            }
        }
    </script>
</body>
</html>`,
		upnpBadgeClass, upnpBadgeText,
		duckBadgeClass, duckBadgeText,
		qrBase64,
		pairURL,
		cfg.DuckDomain,
		cfg.DuckToken,
		map[bool]string{true: "alert-success", false: "alert-info"}[duckStatus.LastSuccess],
		map[bool]string{true: "block", false: "none"}[duckStatus.Enabled],
		duckStatus.LastMessage,
		map[bool]string{true: "✅ Activo", false: "❌ No detectado"}[upnpReport.Active],
		map[bool]string{true: "⚠️ CGNAT", false: "✅ Directa"}[upnpReport.HasCGNAT],
		map[bool]string{true: upnpReport.RouterExternalIP, false: "-"}[upnpReport.RouterExternalIP != ""],
		upnpReport.PublicInternetIP,
		map[bool]string{true: "alert-warning", false: map[bool]string{true: "alert-success", false: "alert-info"}[upnpReport.Active]}[upnpReport.HasCGNAT],
		upnpReport.Message,
		sigServer.ClientCount(),
		cfg.GetPublicIP(),
		cfg.HTTPPort,
		cfg.TURNPort,
		string(configJSONBytes),
		pairURL,
	)

	fmt.Fprint(w, html)
}
