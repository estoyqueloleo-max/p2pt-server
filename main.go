package main

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
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
	"os/exec"
	"path/filepath"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/logging"
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
	EnableUPnP       bool
	EnableMDNS       bool
	EnableAutoUpdate bool
	TopicID          string
	Realm            string
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

type ScannedNetwork struct {
	SSID   string `json:"ssid"`
	Signal int    `json:"signal"`
}

func scanWiFiNetworks() []ScannedNetwork {
	var networks []ScannedNetwork
	seen := make(map[string]bool)

	out, err := exec.Command("iw", "dev", "wlan0", "scan").Output()
	if err != nil || len(out) == 0 {
		out, _ = exec.Command("iwlist", "wlan0", "scan").Output()
	}

	lines := strings.Split(string(out), "\n")
	currentSignal := -100
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "signal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if sig, err := strconv.ParseFloat(parts[1], 64); err == nil {
					currentSignal = int(sig)
				}
			}
		} else if strings.HasPrefix(line, "SSID:") {
			ssid := strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
			if ssid != "" && !seen[ssid] {
				seen[ssid] = true
				networks = append(networks, ScannedNetwork{SSID: ssid, Signal: currentSignal})
			}
			currentSignal = -100
		} else if strings.HasPrefix(line, "ESSID:") {
			ssid := strings.Trim(strings.TrimPrefix(line, "ESSID:"), "\"'\r ")
			if ssid != "" && !seen[ssid] {
				seen[ssid] = true
				networks = append(networks, ScannedNetwork{SSID: ssid, Signal: currentSignal})
			}
			currentSignal = -100
		}
	}
	return networks
}

func main() {
	serverStartTime := time.Now()
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
	appURL := flag.String("app-url", "https://estoyqueloleo-max.github.io/p2pt", "Base URL of Pingo app")
	topicFlag := flag.String("topic", "pingo-public-mesh", "P2P Community Topic / Swarm Network")
	enableMDNS := flag.Bool("mdns", true, "Enable local mDNS / Zeroconf advertising")
	noMDNS := flag.Bool("no-mdns", false, "Disable local mDNS advertising")
	enableAutoUpdate := flag.Bool("auto-update", false, "Enable background auto-updates from GitHub Releases")

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
	if envTopic := os.Getenv("TOPIC_ID"); envTopic != "" {
		*topicFlag = envTopic
	}
	if envAppURL := os.Getenv("APP_URL"); envAppURL != "" {
		*appURL = envAppURL
	}
	if envUPnP := os.Getenv("ENABLE_UPNP"); envUPnP == "false" || envUPnP == "0" {
		*enableUPnP = false
	}
	if *noUPnP {
		*enableUPnP = false
	}
	if *noMDNS || os.Getenv("ENABLE_MDNS") == "false" || os.Getenv("ENABLE_MDNS") == "0" {
		*enableMDNS = false
	}
	if os.Getenv("AUTO_UPDATE") == "true" || os.Getenv("AUTO_UPDATE") == "1" {
		*enableAutoUpdate = true
	}

	cfg := &Config{
		HTTPPort:         *httpPort,
		TURNPort:         *turnPort,
		PublicIP:         *publicIPFlag,
		DuckDomain:       *duckDomain,
		DuckToken:        *duckToken,
		EnableUPnP:       *enableUPnP,
		EnableMDNS:       *enableMDNS,
		EnableAutoUpdate: *enableAutoUpdate,
		TopicID:          *topicFlag,
		Realm:            *realm,
		Username:         *username,
		Password:         *password,
		AuthSecret:       *authSecret,
		MinRelayPort:     *minPort,
		MaxRelayPort:     *maxPort,
		EnableTLS:        *enableTLS,
		TLSCertFile:      *tlsCert,
		TLSKeyFile:       *tlsKey,
		AppPublicURL:     *appURL,
	}

	// Interactive Wizard if requested
	if *runWizard {
		RunCLIWizard(cfg)
	}

	go SyncSystemClock()
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
	turnIP := net.ParseIP(cfg.PublicIP)
	if turnIP == nil {
		turnIP = net.ParseIP(detectedPublicIP)
	}
	if turnIP == nil {
		turnIP = net.ParseIP("127.0.0.1")
	}

	// 1. Initialize Turn Monitor & Pion TURN Server
	turnMonitor := NewTurnMonitor()

	turnUDPListener, err := net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.TURNPort))
	if err != nil {
		log.Fatalf("[TURN] Failed to listen on UDP port %d (Dual-Stack): %v", cfg.TURNPort, err)
	}
	defer turnUDPListener.Close()

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm:         cfg.Realm,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		AuthHandler: func(u string, r string, srcAddr net.Addr) ([]byte, bool) {
			log.Printf("[TURN-Auth] Auth request for user: %s, realm: %s from %s", u, r, srcAddr)
			if turnMonitor.CheckIPBlocked(srcAddr) {
				log.Printf("[TURN-Auth] IP %s bloqueada temporalmente por intentos fallidos", srcAddr)
				return nil, false
			}

			if u == cfg.Username {
				turnMonitor.RecordAuthAttempt(u, srcAddr, true)
				return turn.GenerateAuthKey(u, r, cfg.Password), true
			}
			if cfg.AuthSecret != "" {
				parts := strings.Split(u, ":")
				if len(parts) >= 2 {
					mac := hmac.New(sha1.New, []byte(cfg.AuthSecret))
					mac.Write([]byte(u))
					expectedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))
					turnMonitor.RecordAuthAttempt(u, srcAddr, true)
					return turn.GenerateAuthKey(u, r, expectedPassword), true
				}
				turnMonitor.RecordAuthAttempt(u, srcAddr, true)
				return turn.GenerateAuthKey(u, r, cfg.AuthSecret), true
			}
			turnMonitor.RecordAuthAttempt(u, srcAddr, false)
			log.Printf("[TURN-Auth] Auth failed for user: %s", u)
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

	// 2. Initialize PeerJS Signaling Server & WebTorrent Tracker
	sigServer := NewSignalingServer(cfg)
	tracker := NewWebTorrentTracker()
	mux := http.NewServeMux()

	var currentTLSCert tls.Certificate
	var tlsMu sync.RWMutex

	mux.HandleFunc("/tracker", tracker.HandleWebSocket)
	mux.HandleFunc("/announce", tracker.HandleWebSocket)
	log.Printf("[Tracker] Endpoint WebTorrent WebSocket listo en ws://0.0.0.0:%d/tracker", cfg.HTTPPort)

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
			_ = SaveConfigToEnv(cfg)
			duckMgr.StartBackgroundSync()

			go func() {
				log.Printf("[DuckDNS] Solicitando certificado oficial Let's Encrypt para %s vía DNS-01...", cfg.DuckDomain)
				if newCert, err := ObtainOrRenewDuckDNSCert(cfg); err == nil {
					tlsMu.Lock()
					currentTLSCert = newCert
					tlsMu.Unlock()
					log.Printf("[DuckDNS] 🎉 Certificado SSL Let's Encrypt activado en caliente para %s.duckdns.org", cfg.DuckDomain)
				} else {
					log.Printf("[DuckDNS] ⚠️ No se pudo obtener certificado Let's Encrypt: %v", err)
				}
			}()
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

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		upnpReport := upnpMgr.GetReport()
		duckStatus := duckMgr.GetStatus()
		status := map[string]interface{}{
			"status":          "ok",
			"version":         CurrentVersion,
			"uptime_seconds":  int(time.Since(serverStartTime).Seconds()),
			"public_host":     cfg.GetPublicIP(),
			"http_port":       cfg.HTTPPort,
			"turn_port":       cfg.TURNPort,
			"topic_id":        cfg.TopicID,
			"info_hash":       DeriveInfoHash(cfg.TopicID),
			"upnp":            upnpReport,
			"duckdns":         duckStatus,
			"mdns":            cfg.EnableMDNS,
			"auto_update":     cfg.EnableAutoUpdate,
			"active_clients":  sigServer.ClientCount(),
			"tracker_swarms":  tracker.SwarmCount(),
		}
		_ = json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprintf(w, `{"status":"ok","clients":%d,"turn":"active"}`+"\n", sigServer.ClientCount())
	})

	mux.HandleFunc("/turn-credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		ttl := 86400
		expiry := time.Now().Unix() + int64(ttl)
		user := r.URL.Query().Get("user")
		if user == "" {
			user = "pingo-client"
		}
		turnUser := fmt.Sprintf("%d:%s", expiry, user)
		mac := hmac.New(sha1.New, []byte(cfg.AuthSecret))
		mac.Write([]byte(turnUser))
		turnPass := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		turnURI := fmt.Sprintf("turn:%s:%d?transport=udp", cfg.GetPublicIP(), cfg.TURNPort)
		stunURI := fmt.Sprintf("stun:%s:%d", cfg.GetPublicIP(), cfg.TURNPort)

		resp := map[string]interface{}{
			"iceServers": []map[string]interface{}{
				{
					"urls":       []string{turnURI, stunURI},
					"username":   turnUser,
					"credential": turnPass,
				},
			},
			"ttl": ttl,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/turn", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/turn-credentials", http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			DuckDomain string `json:"duck_domain"`
			DuckToken  string `json:"duck_token"`
			TopicID    string `json:"topic_id"`
			UPnP       *bool  `json:"upnp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if payload.DuckDomain != "" {
			cfg.DuckDomain = strings.TrimSpace(payload.DuckDomain)
			cfg.SetPublicIP(formatFullDomain(cfg.DuckDomain))
		}
		if payload.DuckToken != "" {
			cfg.DuckToken = strings.TrimSpace(payload.DuckToken)
		}
		if payload.TopicID != "" {
			cfg.TopicID = strings.TrimSpace(payload.TopicID)
		}
		if payload.UPnP != nil {
			cfg.EnableUPnP = *payload.UPnP
		}
		_ = SaveConfigToEnv(cfg)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  cfg,
		})
	})
	mux.HandleFunc("/api/turn/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		sessions, activeCount, blockedCount := turnMonitor.GetActiveSessions()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active_sessions_count": activeCount,
			"blocked_ips_count":     blockedCount,
			"sessions":              sessions,
		})
	})

	
	


	mux.HandleFunc("/api/wifi/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		networks := scanWiFiNetworks()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"networks": networks,
		})
	})

	mux.HandleFunc("/api/wifi/configure", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			SSID     string `json:"ssid"`
			Password string `json:"password"`
			IPMode   string `json:"ip_mode"`
			IP       string `json:"ip"`
			Netmask  string `json:"netmask"`
			Gateway  string `json:"gateway"`
			DNS      string `json:"dns"`
			Reboot   bool   `json:"reboot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		ssid := strings.TrimSpace(payload.SSID)
		pass := strings.TrimSpace(payload.Password)
		if ssid == "" {
			http.Error(w, `{"error":"SSID cannot be empty"}`, http.StatusBadRequest)
			return
		}

		bootDir := "/media/mmcblk0p1"
		if _, err := os.Stat(bootDir); os.IsNotExist(err) {
			bootDir = "/boot"
		}

		_ = exec.Command("mount", "-o", "remount,rw", bootDir).Run()

		wifiFile := filepath.Join(bootDir, "wifi.txt")
		wifiContent := fmt.Sprintf("SSID=%s\nPASS=%s\n", ssid, pass)
		_ = os.WriteFile(wifiFile, []byte(wifiContent), 0644)

		ipFile := filepath.Join(bootDir, "ip.txt")
		if payload.IPMode == "static" && payload.IP != "" {
			netmask := payload.Netmask
			if netmask == "" {
				netmask = "255.255.255.0"
			}
			gateway := payload.Gateway
			if gateway == "" {
				gateway = "192.168.1.1"
			}
			dns := payload.DNS
			if dns == "" {
				dns = "1.1.1.1 8.8.8.8"
			}
			ipContent := fmt.Sprintf("IP=%s\nNETMASK=%s\nGATEWAY=%s\nDNS=%s\n", payload.IP, netmask, gateway, dns)
			_ = os.WriteFile(ipFile, []byte(ipContent), 0644)
		} else {
			_ = os.Remove(ipFile)
		}

		_ = exec.Command("sync").Run()

		// Enviar respuesta inmediatamente antes de lbu y reboot
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Configuración guardada en la MicroSD. Reiniciando Raspberry Pi...",
			"reboot":  payload.Reboot,
		})

		if payload.Reboot {
			go func() {
				time.Sleep(500 * time.Millisecond)
				if _, err := exec.LookPath("lbu"); err == nil {
					_ = exec.Command("lbu", "commit", "-d").Run()
				}
				_ = exec.Command("sync").Run()
				time.Sleep(500 * time.Millisecond)
				for _, cmd := range []string{"/sbin/reboot", "/usr/sbin/reboot", "reboot"} {
					_ = exec.Command(cmd, "-f").Start()
					_ = exec.Command(cmd).Start()
				}
			}()
		}
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
			renderDashboard(w, r, cfg, sigServer, upnpMgr, duckMgr, tracker, turnMonitor)
			return
		}

		http.NotFound(w, r)
	})

	// 3. Initialize Swarm Announcer (P2P Topic Federation)
	swarmAnnouncer := NewSwarmAnnouncer(cfg)
	swarmAnnouncer.Start()

	// 5. Initialize mDNS Local Discovery
	var mdnsServer *MDNSServer
	if cfg.EnableMDNS {
		mdns, err := StartMDNSServer(cfg.HTTPPort, cfg.TURNPort, "Pingo Server", "pingo")
		if err != nil {
			log.Printf("[mDNS] Advertencia: no se pudo iniciar mDNS: %v", err)
		} else {
			mdnsServer = mdns
		}
	}

	// 6. Initialize Auto-Updater if enabled
	updater := NewUpdaterManager("estoyqueloleo-max", "p2pt-server")
	if cfg.EnableAutoUpdate {
		log.Println("[Updater] Auto-actualizador activado en segundo plano (Revisión cada 12h).")
		updater.StartBackgroundCheck()
	}

	// 7. Initialize TLS Certificates (Let's Encrypt via DuckDNS DNS-01 or Local/Self-Signed fallback)
	cert, errTLS := EnsureTLSCertificates(cfg)
	if errTLS == nil {
		cfg.EnableTLS = true
		tlsMu.Lock()
		currentTLSCert = cert
		tlsMu.Unlock()
	} else {
		log.Printf("[TLS] Advertencia: no se pudo iniciar TLS automático: %v", errTLS)
	}

	_, configJSON, pairURL := generatePairConfig(cfg)
	printBanner(cfg, pairURL, configJSON, upnpMgr.GetReport(), duckMgr.GetStatus())

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: mux,
	}

	go func() {
		if cfg.EnableTLS {
			httpServer.TLSConfig = &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					tlsMu.RLock()
					defer tlsMu.RUnlock()
					return &currentTLSCert, nil
				},
			}
			log.Printf("[Signaling] 🔒 Servidor Seguro HTTPS / WSS activo en :%d (Dual-Stack IPv4/IPv6)...", cfg.HTTPPort)

			// Iniciar tarea de renovación automática de certificados si se usa DuckDNS
			if cfg.DuckDomain != "" && cfg.DuckToken != "" {
				go func() {
					renewTicker := time.NewTicker(24 * time.Hour)
					defer renewTicker.Stop()
					for range renewTicker.C {
						log.Println("[ACME] Verificando validez y renovación de certificado Let's Encrypt...")
						if newCert, err := ObtainOrRenewDuckDNSCert(cfg); err == nil {
							tlsMu.Lock()
							currentTLSCert = newCert
							tlsMu.Unlock()
						}
					}
				}()
			}

			if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Signaling] Error HTTPS: %v", err)
			}
		} else {
			log.Printf("[Signaling] 🌐 Servidor HTTP / WS activo en :%d (Dual-Stack IPv4/IPv6)...", cfg.HTTPPort)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Signaling] Error HTTP: %v", err)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[Server] Apagando el servidor con seguridad...")
	if swarmAnnouncer != nil {
		swarmAnnouncer.Stop()
	}
	if mdnsServer != nil {
		mdnsServer.Close()
	}
	if cfg.EnableAutoUpdate {
		updater.Stop()
	}
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
	fmt.Printf(" • Red P2P / Topic    : %s (InfoHash: %s)\n", cfg.TopicID, DeriveInfoHash(cfg.TopicID))
	fmt.Printf(" • Señalización (WS)  : http%s://%s:%d\n", map[bool]string{true: "s", false: ""}[cfg.EnableTLS], cfg.GetPublicIP(), cfg.HTTPPort)
	fmt.Printf(" • WebTorrent Tracker : ws%s://%s:%d/tracker\n", map[bool]string{true: "s", false: ""}[cfg.EnableTLS], cfg.GetPublicIP(), cfg.HTTPPort)
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
		if duck.CurrentIPv6 != "" {
			fmt.Printf(" • IPv6 Global        : ✅ %s (Sin CGNAT / AAAA activo)\n", duck.CurrentIPv6)
		}
	} else {
		fmt.Println(" • DuckDNS DDNS       : ℹ️ No configurado (usando IP directa)")
		if ipv6 := GetGlobalIPv6(); ipv6 != "" {
			fmt.Printf(" • IPv6 Global        : 🌐 %s (Disponible en red local/Internet)\n", ipv6)
		}
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

func renderDashboard(w http.ResponseWriter, r *http.Request, cfg *Config, sigServer *SignalingServer, upnpMgr *UPnPManager, duckMgr *DuckDNSManager, tracker *WebTorrentTracker, turnMonitor *TurnMonitor) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	currentWiFiSSID := ""
	for _, f := range []string{"/media/mmcblk0p1/wifi.txt", "/boot/wifi.txt"} {
		if data, err := os.ReadFile(f); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToUpper(line), "SSID=") {
					currentWiFiSSID = strings.Trim(strings.TrimPrefix(line, "SSID="), "\"'\r ")
					break
				}
			}
		}
		if currentWiFiSSID != "" {
			break
		}
	}


	_, configJSONBytes, pairURL := generatePairConfig(cfg)
	upnpReport := upnpMgr.GetReport()
	duckStatus := duckMgr.GetStatus()
	sessions, activeCount, blockedCount := turnMonitor.GetActiveSessions()

	var sessionsRows strings.Builder
	if len(sessions) == 0 {
		sessionsRows.WriteString(`<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:14px;">No hay sesiones TURN de vídeo activas en este instante.</td></tr>`)
	} else {
		for _, s := range sessions {
			remaining := time.Until(s.ExpiresAt)
			remainingStr := fmt.Sprintf("%dm", int(remaining.Minutes()))
			if remaining.Hours() >= 1 {
				remainingStr = fmt.Sprintf("%dh %dm", int(remaining.Hours()), int(remaining.Minutes())%60)
			}
			if remaining <= 0 {
				remainingStr = "Expirado"
			}

			statusBadge := `<span class="badge badge-success">🟢 Activo</span>`
			if s.Status == "expired" {
				statusBadge = `<span class="badge badge-muted">⏳ Expirado</span>`
			} else if s.Status == "blocked" {
				statusBadge = `<span class="badge badge-error">🚫 Bloqueado</span>`
			}

			trafficMB := float64(s.BytesRelayed) / (1024 * 1024)

			sessionsRows.WriteString(fmt.Sprintf(`<tr>
				<td style="padding:10px; font-family:monospace; color:var(--accent);">%s</td>
				<td style="padding:10px;">%s</td>
				<td style="padding:10px;">%.2f MB</td>
				<td style="padding:10px;">%s</td>
				<td style="padding:10px;">%s</td>
			</tr>`, s.Username, s.ClientIP, trafficMB, remainingStr, statusBadge))
		}
	}

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

	topicInfoHash := DeriveInfoHash(cfg.TopicID)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pingo Standalone Server Dashboard</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card-bg: #111827;
            --border: #1f2937;
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
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
        }
        .badges-row {
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
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
        .badge-muted { background: rgba(148, 163, 184, 0.1); color: var(--text-muted); border: 1px solid rgba(148, 163, 184, 0.2); }
        .dot { width: 8px; height: 8px; border-radius: 50%%; display: inline-block; background: currentColor; }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
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
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .qr-box img { display: block; border-radius: 4px; }
        
        .btn {
            background: var(--accent);
            color: #0b0f19;
            font-weight: 600;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.95rem;
            transition: background 0.15s ease;
        }
        .btn:hover { background: var(--accent-hover); }
        .btn-secondary {
            background: rgba(255,255,255,0.08);
            color: var(--text-main);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.12); }
        
        .form-row {
            display: flex;
            gap: 10px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        .form-group {
            flex: 1;
            min-width: 200px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .form-group label {
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 500;
        }
        .form-control {
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 9px 12px;
            color: white;
            font-size: 0.9rem;
        }
        .form-control:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }
        .stat {
            background: rgba(0,0,0,0.2);
            padding: 12px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .stat-label { color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; }
        .stat-val { font-size: 1.05rem; font-weight: 700; margin-top: 4px; color: #e2e8f0; }
        pre {
            background: #090d16;
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            color: var(--accent);
            font-size: 0.82rem;
        }
        .alert { padding: 12px; border-radius: 8px; font-size: 0.88rem; margin-top: 12px; }
        .alert-success { background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.25); color: #6ee7b7; }
        .alert-warning { background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.25); color: #fcd34d; }
        .alert-info { background: rgba(6, 182, 212, 0.12); border: 1px solid rgba(6, 182, 212, 0.25); color: #67e8f9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📡 Nodo Privado Pingo</h1>
            <div class="badges-row">
                <div class="badge badge-success"><span class="dot"></span> Señalización & Relé Activos</div>
                <div class="badge badge-success"><span class="dot"></span> mDNS: pingo.local</div>
                <div class="badge %s" id="upnp-badge"><span class="dot"></span> %s</div>
                <div class="badge %s" id="duck-badge"><span class="dot"></span> %s</div>
            </div>
        </div>

        <div class="card qr-section">
            <h2 style="margin:0;">📲 Vinculación Rápida con la App Pingo</h2>
            <p style="color: var(--text-muted); margin: 0; font-size: 0.95rem;">Escanea el QR o abre el enlace para importar la configuración:</p>
            <div class="qr-box">
                <img id="qr-img" src="data:image/png;base64,%s" alt="QR de Vinculación" width="220" height="220">
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; justify-content:center;">
                <a id="pair-btn" href="%s" target="_blank" class="btn">🚀 Abrir Pingo con este Servidor</a>
                <button id="copy-btn" onclick="copyPairURL()" class="btn btn-secondary">📋 Copiar Enlace</button>
            </div>
        </div>

        <div class="card">
            <h3>
                <span>🔑 Red Comunitaria & Topic P2P</span>
                <span class="badge badge-success" style="font-size:0.75rem;">WebTorrent Tracker Activo</span>
            </h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0;">Los móviles y amigos que configuren esta misma Red Comunitaria en su app Pingo descubrirán automáticamente este servidor TURN sin introducir IPs.</p>
            <div class="form-row">
                <div class="form-group">
                    <label>Nombre de Red / Topic ID</label>
                    <input type="text" id="topic-id-input" class="form-control" placeholder="ej. amigos-valencia" value="%s">
                </div>
                <div class="form-group">
                    <label>InfoHash Swarm (Auto-generado)</label>
                    <input type="text" class="form-control" value="%s" readonly style="color:var(--accent); background:rgba(0,0,0,0.4);">
                </div>
                <div class="form-group" style="flex:0.5; min-width:140px; justify-content:flex-end;">
                    <button id="save-topic-btn" onclick="saveTopicID()" class="btn" style="width:100%%;">💾 Guardar Red</button>
                </div>
            </div>
            <div id="topic-alert" class="alert alert-success" style="display:none;"></div>
        </div>

        
                <!-- Asistente de Puesta en Marcha (Wizard) -->
        <div class="card" style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%%, rgba(15, 23, 42, 0.85) 100%%); border: 1px solid rgba(99, 102, 241, 0.3);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h3 style="margin: 0; color: #818cf8;">🚀 Asistente de Configuración Rápida</h3>
                <span style="font-size: 0.8rem; color: var(--text-muted);">Nodo Autónomo P2P</span>
            </div>
            <div style="display: flex; gap: 8px; font-size: 0.82rem; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 140px; background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #3b82f6;">
                    <b>1. Wi-Fi & Red</b><br><span style="color:var(--text-muted); font-size:0.75rem;">Conexión a tu router</span>
                </div>
                <div style="flex: 1; min-width: 140px; background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #8b5cf6;">
                    <b>2. TLS & nip.io</b><br><span style="color:var(--text-muted); font-size:0.75rem;">WSS Seguro nativo</span>
                </div>
                <div style="flex: 1; min-width: 140px; background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #10b981;">
                    <b>3. Vincular App</b><br><span style="color:var(--text-muted); font-size:0.75rem;">Escanear QR o enlace</span>
                </div>
            </div>
        </div>

        <div class="card" style="border: 2px solid var(--accent); background: rgba(59, 130, 246, 0.05);">
            <h3>
                <span>📶 1. Conectar a mi Router Wi-Fi & Salida a Internet</span>
                <span class="badge badge-warning" style="font-size:0.75rem;">Aprovisionamiento Wi-Fi</span>
            </h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0 0 14px 0;">
                Elige la red Wi-Fi de tu casa (2.4 GHz) del desplegable para que la Raspberry Pi se conecte a Internet, salga del modo Hotspot y se registre con WSS/HTTPS.
            </p>

            <div class="form-row">
                <div class="form-group" style="flex: 1.5;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <label style="margin:0;">Red Wi-Fi Detectada</label>
                        <button type="button" id="scan-wifi-btn" onclick="scanWiFiNetworks()" class="btn" style="background: rgba(255,255,255,0.08); font-size: 0.75rem; padding: 2px 8px;">
                            🔄 Actualizar Redes
                        </button>
                    </div>
                    <select id="wifi-select" class="form-control" onchange="handleWiFiSelectChange(this.value)">
                        <option value="">⏳ Escaneando redes cercanas...</option>
                    </select>
                    <input type="text" id="wifi-ssid-input" class="form-control" placeholder="Escribe el nombre de red (SSID)" value="%s" style="display:none; margin-top:6px;">
                </div>
                <div class="form-group" style="flex: 1.5;">
                    <label>Contraseña Wi-Fi</label>
                    <input type="password" id="wifi-pass-input" class="form-control" placeholder="Contraseña de tu red">
                </div>
            </div>
            
            <div style="margin-top: 14px; display: flex; align-items: center; gap: 20px;">
                <label style="font-size: 0.88rem; color: var(--text); display: flex; align-items: center; gap: 6px; cursor: pointer;">
                    <input type="radio" name="ip_mode" value="dhcp" checked onchange="toggleIPFields()"> 🟢 DHCP Automático (Recomendado)
                </label>
                <label style="font-size: 0.88rem; color: var(--text); display: flex; align-items: center; gap: 6px; cursor: pointer;">
                    <input type="radio" name="ip_mode" value="static" onchange="toggleIPFields()"> ⚙️ IP Estática Fija
                </label>
            </div>

            <div id="static-ip-container" class="form-row" style="display: none; margin-top: 12px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; border: 1px solid var(--border);">
                <div class="form-group">
                    <label>IP Fija Deseada</label>
                    <input type="text" id="wifi-ip-input" class="form-control" placeholder="192.168.1.50" value="192.168.1.50">
                </div>
                <div class="form-group">
                    <label>Puerta de Enlace (Router)</label>
                    <input type="text" id="wifi-gw-input" class="form-control" placeholder="192.168.1.1" value="192.168.1.1">
                </div>
                <div class="form-group">
                    <label>Máscara de Red</label>
                    <input type="text" id="wifi-mask-input" class="form-control" placeholder="255.255.255.0" value="255.255.255.0">
                </div>
                <div class="form-group">
                    <label>Servidores DNS</label>
                    <input type="text" id="wifi-dns-input" class="form-control" placeholder="1.1.1.1 8.8.8.8" value="1.1.1.1 8.8.8.8">
                </div>
            </div>

            <div style="margin-top: 16px;">
                <button type="button" id="save-wifi-btn" onclick="saveWiFiAndReboot()" class="btn" style="width: 100%%; padding: 12px; font-weight: bold; background: #3b82f6; color: white; border-radius: 6px; cursor: pointer;">
                    💾 Guardar y Reiniciar Raspberry Pi
                </button>
            </div>
            <div id="wifi-alert" class="alert" style="display: none; margin-top: 14px;"></div>
        </div>

                <div class="card" style="border: 1px solid rgba(234, 179, 8, 0.4); background: rgba(234, 179, 8, 0.03);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0;">
                    <span>🦆 2. Dominio Global & Acceso desde Fuera de Casa (DuckDNS)</span>
                </h3>
                <span class="badge badge-warning" style="font-size:0.75rem;">Opcional pero Recomendado</span>
            </div>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0 0 16px 0;">
                DuckDNS te proporciona un dominio público gratuito (ej: <code>mi-nodo.duckdns.org</code>) para conectar a tu Raspberry Pi por <b>HTTPS/WSS</b> desde la calle o red móvil sin pagar nada ni configurar IPs dinámicas.
            </p>

            <!-- Guía Rápida por Pasos -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-bottom: 16px;">
                <div style="background: rgba(0,0,0,0.25); padding: 10px 14px; border-radius: 8px; border-left: 3px solid #eab308; font-size: 0.84rem;">
                    <b style="color:#fde047;">Paso 1: Entrar a DuckDNS</b>
                    <p style="margin: 4px 0 6px 0; color: var(--text-muted); font-size: 0.78rem;">Inicia sesión gratis con Google o GitHub:</p>
                    <a href="https://www.duckdns.org" target="_blank" class="btn btn-secondary" style="font-size: 0.75rem; padding: 4px 8px; display: inline-block;">
                        ↗️ Abrir DuckDNS.org
                    </a>
                </div>
                <div style="background: rgba(0,0,0,0.25); padding: 10px 14px; border-radius: 8px; border-left: 3px solid #3b82f6; font-size: 0.84rem;">
                    <b style="color:#93c5fd;">Paso 2: Crear tu Subdominio</b>
                    <p style="margin: 4px 0 0 0; color: var(--text-muted); font-size: 0.78rem;">En la casilla <i>domains</i>, escribe un nombre (ej. <code>pingo-casa</code>) y pulsa <i>add domain</i>.</p>
                </div>
                <div style="background: rgba(0,0,0,0.25); padding: 10px 14px; border-radius: 8px; border-left: 3px solid #10b981; font-size: 0.84rem;">
                    <b style="color:#6ee7b7;">Paso 3: Copiar tu Token</b>
                    <p style="margin: 4px 0 0 0; color: var(--text-muted); font-size: 0.78rem;">Copia el <i>token</i> alfanumérico que aparece arriba en la barra de DuckDNS.</p>
                </div>
            </div>

            <!-- Formulario de Configuración -->
            <div class="form-row" style="align-items: flex-end;">
                <div class="form-group" style="flex: 1.5;">
                    <label>Tu Subdominio Elegido</label>
                    <div style="display: flex; align-items: center; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 6px; overflow: hidden;">
                        <input type="text" id="duck-domain-input" class="form-control" placeholder="ej. pingo-casa" value="%s" style="border: none; background: transparent;" oninput="cleanDuckDomain(this)">
                        <span style="padding: 0 10px; color: var(--text-muted); font-size: 0.85rem; background: rgba(255,255,255,0.05); height: 100%%; display: flex; align-items: center; border-left: 1px solid var(--border);">.duckdns.org</span>
                    </div>
                </div>
                <div class="form-group" style="flex: 1.5;">
                    <label>Tu Token Privado de DuckDNS</label>
                    <input type="password" id="duck-token-input" class="form-control" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value="%s">
                </div>
                <div class="form-group" style="flex: 1; min-width: 160px;">
                    <button type="button" id="save-duck-btn" onclick="saveDuckDNS()" class="btn" style="width: 100%%; padding: 10px; font-weight: bold; background: #eab308; color: #000; border-radius: 6px; cursor: pointer;">
                        🚀 Probar y Activar
                    </button>
                </div>
            </div>
            <div id="duck-alert" class="alert %s" style="display:%s;">%s</div>
        </div>

        <div class="card">
            <h3>📊 Métricas del Servidor</h3>
            <div class="grid">
                <div class="stat">
                    <div class="stat-label">Clientes Señalización</div>
                    <div class="stat-val">%d</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Swarm WebTorrent</div>
                    <div class="stat-val">%d activos</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Puerto Señalización (WS)</div>
                    <div class="stat-val">%d</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Puerto TURN/STUN</div>
                    <div class="stat-val">%d</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>
                <span>🛡️ Sesiones TURN Activas & Control de Abusos</span>
                <span class="badge %s" style="font-size:0.75rem;">%d Activas &bull; %d IPs Bloqueadas</span>
            </h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0 0 12px 0;">Monitor en tiempo real de retransmisión de vídeo WebRTC y expiración de tokens dinámicos.</p>
            <div style="overflow-x:auto;">
                <table style="width:100%%; border-collapse:collapse; font-size:0.88rem; text-align:left;">
                    <thead>
                        <tr style="border-bottom:1px solid var(--border); color:var(--text-muted); font-size:0.75rem; text-transform:uppercase;">
                            <th style="padding:8px 10px;">Usuario / Token</th>
                            <th style="padding:8px 10px;">IP Origen</th>
                            <th style="padding:8px 10px;">Tráfico Relé</th>
                            <th style="padding:8px 10px;">Expiración</th>
                            <th style="padding:8px 10px;">Estado</th>
                        </tr>
                    </thead>
                    <tbody>
                        %s
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h3>⚙️ Configuración JSON para Pingo</h3>
            <pre id="json-preview">%s</pre>
        </div>
    </div>

    <script>
        let currentPairURL = "%s";

        function toggleIPFields() {
            const isStatic = document.querySelector('input[name="ip_mode"]:checked').value === 'static';
            const container = document.getElementById('static-ip-container');
            if (container) {
                container.style.display = isStatic ? 'flex' : 'none';
            }
        }

        function handleWiFiSelectChange(val) {
            const manualInput = document.getElementById('wifi-ssid-input');
            const passInput = document.getElementById('wifi-pass-input');
            if (val === '__MANUAL__') {
                manualInput.style.display = 'block';
                manualInput.value = '';
                manualInput.focus();
            } else if (val) {
                manualInput.style.display = 'none';
                manualInput.value = val;
                if (passInput) passInput.focus();
            }
        }

        async function scanWiFiNetworks() {
            const btn = document.getElementById('scan-wifi-btn');
            const select = document.getElementById('wifi-select');
            const manualInput = document.getElementById('wifi-ssid-input');
            if (btn) {
                btn.disabled = true;
                btn.innerText = "⏳ Buscando...";
            }

            try {
                const res = await fetch('/api/wifi/scan');
                const data = await res.json();
                if (data.networks && data.networks.length > 0) {
                    const currentVal = manualInput ? manualInput.value : '';
                    select.innerHTML = '<option value="">-- Selecciona tu red Wi-Fi (' + data.networks.length + ' disponibles) --</option>';
                    let matched = false;
                    data.networks.forEach(n => {
                        const opt = document.createElement('option');
                        opt.value = n.ssid;
                        opt.innerText = '📶 ' + n.ssid + (n.signal ? ' (' + n.signal + ' dBm)' : '');
                        if (currentVal && n.ssid === currentVal) {
                            opt.selected = true;
                            matched = true;
                        }
                        select.appendChild(opt);
                    });
                    const manualOpt = document.createElement('option');
                    manualOpt.value = '__MANUAL__';
                    manualOpt.innerText = '✏️ Escribir otra red (SSID manual u oculta)...';
                    select.appendChild(manualOpt);
                    if (matched) {
                        manualInput.style.display = 'none';
                    }
                } else {
                    select.innerHTML = '<option value="__MANUAL__">✏️ Escribir red manualmente (Sin escaneo rápido)</option>';
                    if (manualInput) manualInput.style.display = 'block';
                }
            } catch (e) {
                select.innerHTML = '<option value="__MANUAL__">✏️ Escribir red manualmente</option>';
                if (manualInput) manualInput.style.display = 'block';
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = "🔄 Actualizar Redes";
                }
            }
        }

        window.addEventListener('DOMContentLoaded', () => {
            scanWiFiNetworks();
        });

        async function saveWiFiAndReboot() {
            const ssid = document.getElementById("wifi-ssid-input").value.trim();
            const password = document.getElementById("wifi-pass-input").value.trim();
            const ipMode = document.querySelector('input[name="ip_mode"]:checked').value;
            const ip = document.getElementById("wifi-ip-input").value.trim();
            const netmask = document.getElementById("wifi-mask-input").value.trim();
            const gateway = document.getElementById("wifi-gw-input").value.trim();
            const dns = document.getElementById("wifi-dns-input").value.trim();
            const btn = document.getElementById("save-wifi-btn");
            const alertBox = document.getElementById("wifi-alert");

            if (!ssid) {
                if (alertBox) {
                    alertBox.style.display = "block";
                    alertBox.className = "alert alert-warning";
                    alertBox.innerText = "⚠️ Por favor introduce el nombre de la red Wi-Fi (SSID).";
                }
                return;
            }

            if (btn) {
                btn.disabled = true;
                btn.innerText = "⏳ Guardando en MicroSD y reiniciando...";
            }
            if (alertBox) {
                alertBox.style.display = "block";
                alertBox.className = "alert alert-info";
                alertBox.innerHTML = "⏳ <b>Guardando configuración en la MicroSD...</b>";
            }

            try {
                const res = await fetch("/api/wifi/configure", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        ssid: ssid,
                        password: password,
                        ip_mode: ipMode,
                        ip: ip,
                        netmask: netmask,
                        gateway: gateway,
                        dns: dns,
                        reboot: true
                    })
                });
                const data = await res.json();
                if (data.success) {
                    if (alertBox) {
                        alertBox.className = "alert alert-success";
                        alertBox.innerHTML = "✅ <b>" + data.message + "</b><br><br>👉 La Raspberry Pi se está reiniciando.<br>Vuelve a conectar tu móvil a la Wi-Fi habitual (<b>" + ssid + "</b>) y abre <a href='http://pingo.local:9000/' style='color:var(--accent); font-weight:bold;'>http://pingo.local:9000/</a> en ~30 segundos.";
                    }
                } else {
                    if (alertBox) {
                        alertBox.className = "alert alert-warning";
                        alertBox.innerText = "⚠️ " + data.message;
                    }
                    if (btn) {
                        btn.disabled = false;
                        btn.innerText = "💾 Guardar y Reiniciar Raspberry Pi";
                    }
                }
            } catch (err) {
                if (alertBox) {
                    alertBox.className = "alert alert-success";
                    alertBox.innerHTML = "✅ <b>Configuración enviada. La Raspberry Pi se está reiniciando...</b><br><br>👉 Vuelve a conectar tu móvil a tu Wi-Fi habitual.";
                }
            }
        }

        function copyPairURL() {
            const btn = document.getElementById("copy-btn");
            const originalText = btn ? btn.innerHTML : "📋 Copiar Enlace";
            
            function showSuccess() {
                if (btn) {
                    btn.innerHTML = "✅ ¡Enlace Copiado!";
                    btn.style.background = "#10b981";
                    setTimeout(() => {
                        btn.innerHTML = originalText;
                        btn.style.background = "";
                    }, 2500);
                }
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(currentPairURL).then(showSuccess).catch(() => {
                    fallbackCopy(currentPairURL);
                });
            } else {
                fallbackCopy(currentPairURL);
            }

            function fallbackCopy(text) {
                try {
                    const ta = document.createElement("textarea");
                    ta.value = text;
                    ta.style.position = "fixed";
                    ta.style.opacity = "0";
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand("copy");
                    document.body.removeChild(ta);
                    showSuccess();
                } catch(e) {
                    prompt("Copia este enlace manualmente:", text);
                }
            }
        }

        async function saveTopicID() {
            const topic_id = document.getElementById("topic-id-input").value.trim();
            const btn = document.getElementById("save-topic-btn");
            const alertBox = document.getElementById("topic-alert");

            if (!topic_id) {
                alert("Introduce un nombre de red comunitaria (ej. amigos-valencia).");
                return;
            }

            btn.disabled = true;
            btn.innerText = "⏳ Guardando...";

            try {
                const res = await fetch("/api/config", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ topic_id })
                });
                const data = await res.json();
                alertBox.style.display = "block";
                if (data.success) {
                    alertBox.className = "alert alert-success";
                    alertBox.innerText = "✅ Red Comunitaria guardada con éxito en .env!";
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    alertBox.className = "alert alert-warning";
                    alertBox.innerText = "⚠️ Error guardando configuración.";
                }
            } catch (err) {
                alertBox.style.display = "block";
                alertBox.className = "alert alert-warning";
                alertBox.innerText = "Error: " + err.message;
            } finally {
                btn.disabled = false;
                btn.innerText = "💾 Guardar Red";
            }
        }

                function cleanDuckDomain(input) {
            let val = input.value.trim().toLowerCase();
            val = val.replace('.duckdns.org', '').replace('http://', '').replace('https://', '').replace(/\//g, '');
            input.value = val;
        }

        async function saveDuckDNS() {
            const domainInput = document.getElementById("duck-domain-input");
            const tokenInput = document.getElementById("duck-token-input");
            const domain = domainInput.value.trim().toLowerCase().replace('.duckdns.org', '');
            const token = tokenInput.value.trim();
            const btn = document.getElementById("save-duck-btn");
            const alertBox = document.getElementById("duck-alert");

            if (!domain || !token) {
                alertBox.style.display = "block";
                alertBox.className = "alert alert-warning";
                alertBox.innerText = "⚠️ Por favor introduce el subdominio (ej: pingo-casa) y el token de DuckDNS.";
                return;
            }

            btn.disabled = true;
            btn.innerText = "⏳ Verificando en DuckDNS...";
            alertBox.style.display = "block";
            alertBox.className = "alert alert-info";
            alertBox.innerHTML = "⏳ <b>Contactando con los servidores de DuckDNS y actualizando tu IP pública...</b>";

            try {
                const res = await fetch("/api/duckdns", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, token })
                });
                const data = await res.json();

                if (data.success) {
                    alertBox.className = "alert alert-success";
                    const fullHost = domain + ".duckdns.org";
                    alertBox.innerHTML = "🎉 <b>¡Dominio DuckDNS activado con éxito!</b><br><br>" +
                        "🌐 <b>Tu dominio público:</b> <code>" + fullHost + "</code><br>" +
                        "📲 El código QR y los enlaces de vinculación se han actualizado automáticamente.<br>" +
                        "👉 Enlace directo seguro: <a href='https://" + fullHost + ":9000/' target='_blank' style='color:#6ee7b7; font-weight:bold;'>https://" + fullHost + ":9000/</a>";
                    
                    if (data.pair_url) {
                        currentPairURL = data.pair_url;
                        const pairBtn = document.getElementById("pair-btn");
                        if (pairBtn) pairBtn.href = data.pair_url;
                    }
                    setTimeout(() => window.location.reload(), 3000);
                } else {
                    alertBox.className = "alert alert-warning";
                    alertBox.innerText = "⚠️ Error al activar DuckDNS: " + (data.message || "Verifica que el token y subdominio sean correctos.");
                    btn.disabled = false;
                    btn.innerText = "🚀 Probar y Activar";
                }
            } catch (err) {
                alertBox.style.display = "block";
                alertBox.className = "alert alert-warning";
                alertBox.innerText = "Error contactando con el servidor local: " + err.message;
                btn.disabled = false;
                btn.innerText = "🚀 Probar y Activar";
            }
        }
    </script>
</body>
</html>`,
		upnpBadgeClass, upnpBadgeText,
		duckBadgeClass, duckBadgeText,
		qrBase64,
		pairURL,
		cfg.TopicID,
		topicInfoHash,
		currentWiFiSSID,
		cfg.DuckDomain,
		cfg.DuckToken,
		map[bool]string{true: "alert-success", false: "alert-info"}[duckStatus.LastSuccess],
		map[bool]string{true: "block", false: "none"}[duckStatus.Enabled],
		duckStatus.LastMessage,
		sigServer.ClientCount(),
		tracker.SwarmCount(),
		cfg.HTTPPort,
		cfg.TURNPort,
		map[bool]string{true: "badge-warning", false: "badge-success"}[blockedCount > 0],
		activeCount,
		blockedCount,
		sessionsRows.String(),
		string(configJSONBytes),
		pairURL,
	)

	fmt.Fprint(w, html)
}
