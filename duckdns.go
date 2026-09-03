package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DuckDNSStatus holds current synchronization state
type DuckDNSStatus struct {
	Enabled      bool      `json:"enabled"`
	Domain       string    `json:"domain"`
	FullDomain   string    `json:"full_domain"`
	LastUpdate   time.Time `json:"last_update,omitempty"`
	LastSuccess  bool      `json:"last_success"`
	LastMessage  string    `json:"last_message"`
	CurrentIP    string    `json:"current_ip,omitempty"`
	CurrentIPv6  string    `json:"current_ipv6,omitempty"`
	NextUpdateIn string    `json:"next_update_in,omitempty"`
}

// GetGlobalIPv6 discovers the first global unicast IPv6 address on active non-loopback interfaces
func GetGlobalIPv6() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if isGlobalUnicastIPv6(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

func isGlobalUnicastIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	// Exclude Unique Local Addresses (ULA, fc00::/7)
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return false
	}
	// Exclude Link-Local Unicast (fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

type DuckDNSManager struct {
	mu           sync.RWMutex
	domain       string
	token        string
	interval     time.Duration
	status       DuckDNSStatus
	stopChan     chan struct{}
	onUpdateFunc func(fullDomain, currentIP string)
}

func NewDuckDNSManager(domain, token string, onUpdate func(fullDomain, currentIP string)) *DuckDNSManager {
	mgr := &DuckDNSManager{
		domain:       cleanDuckDomain(domain),
		token:        strings.TrimSpace(token),
		interval:     10 * time.Minute,
		onUpdateFunc: onUpdate,
		stopChan:     make(chan struct{}),
	}

	mgr.status = DuckDNSStatus{
		Enabled:     mgr.domain != "" && mgr.token != "",
		Domain:      mgr.domain,
		FullDomain:  formatFullDomain(mgr.domain),
		LastMessage: "No inicializado",
	}

	return mgr
}

func cleanDuckDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".duckdns.org")
	return d
}

func formatFullDomain(d string) string {
	if d == "" {
		return ""
	}
	if strings.HasSuffix(d, ".duckdns.org") {
		return d
	}
	return fmt.Sprintf("%s.duckdns.org", d)
}

// Update sends an update request to DuckDNS API
func (d *DuckDNSManager) Update(ctx context.Context, customIP string) (bool, string, error) {
	d.mu.Lock()
	domain := d.domain
	token := d.token
	d.mu.Unlock()

	if domain == "" || token == "" {
		return false, "Dominio o Token de DuckDNS no configurados", fmt.Errorf("missing credentials")
	}

	if time.Now().Year() < 2026 {
		SyncSystemClock()
	}

	ipv6 := GetGlobalIPv6()
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s", domain, token, customIP)
	if ipv6 != "" {
		url += fmt.Sprintf("&ipv6=%s", ipv6)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, "Error creando petición HTTP", err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate") {
			log.Println("[DuckDNS] Detectado posible desfase de reloj en certificado TLS. Sincronizando fecha...")
			SyncSystemClock()

			insecureClient := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			req2, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			resp, err = insecureClient.Do(req2)
		}
	}

	if err != nil {
		msg := fmt.Sprintf("Error de conexión con DuckDNS: %v", err)
		d.setStatus(false, msg, "", "")
		return false, msg, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("Error leyendo respuesta de DuckDNS: %v", err)
		d.setStatus(false, msg, "", "")
		return false, msg, err
	}

	bodyStr := strings.TrimSpace(string(bodyBytes))
	fullDom := formatFullDomain(domain)

	if strings.Contains(bodyStr, "OK") {
		msg := fmt.Sprintf("DuckDNS actualizado correctamente (%s)", fullDom)
		if ipv6 != "" {
			msg += fmt.Sprintf(" [IPv6: %s]", ipv6)
		}
		d.setStatus(true, msg, customIP, ipv6)
		if d.onUpdateFunc != nil {
			d.onUpdateFunc(fullDom, customIP)
		}
		log.Printf("[DuckDNS] ✅ %s", msg)
		return true, msg, nil
	}

	msg := "DuckDNS respondió KO (verifica que el subdominio y el Token sean correctos)"
	d.setStatus(false, msg, "", "")
	log.Printf("[DuckDNS] ❌ %s", msg)
	return false, msg, fmt.Errorf("duckdns rejected credentials (KO)")
}

func (d *DuckDNSManager) setStatus(success bool, msg, ip, ipv6 string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.status.Enabled = d.domain != "" && d.token != ""
	d.status.Domain = d.domain
	d.status.FullDomain = formatFullDomain(d.domain)
	d.status.LastUpdate = time.Now()
	d.status.LastSuccess = success
	d.status.LastMessage = msg
	if ip != "" {
		d.status.CurrentIP = ip
	}
	if ipv6 != "" {
		d.status.CurrentIPv6 = ipv6
	}
}

// SetDuckDNSTXTRecord sets the TXT record in DuckDNS for ACME DNS-01 challenges
func SetDuckDNSTXTRecord(ctx context.Context, domain, token, txt string) error {
	cleanDom := cleanDuckDomain(domain)
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&txt=%s", cleanDom, strings.TrimSpace(token), strings.TrimSpace(txt))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error llamando API DuckDNS TXT: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "OK") {
		return fmt.Errorf("duckdns rechazó actualización TXT: %s", string(b))
	}
	log.Printf("[DuckDNS-ACME] TXT record publicado para %s.duckdns.org", cleanDom)
	return nil
}

// ClearDuckDNSTXTRecord clears the TXT record in DuckDNS
func ClearDuckDNSTXTRecord(ctx context.Context, domain, token string) error {
	cleanDom := cleanDuckDomain(domain)
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&txt=&clear=true", cleanDom, strings.TrimSpace(token))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error limpiando TXT en DuckDNS: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "OK") {
		return fmt.Errorf("duckdns rechazó borrado TXT: %s", string(b))
	}
	log.Printf("[DuckDNS-ACME] TXT record limpiado para %s.duckdns.org", cleanDom)
	return nil
}

func (d *DuckDNSManager) StartBackgroundSync() {
	d.mu.RLock()
	enabled := d.domain != "" && d.token != ""
	d.mu.RUnlock()

	if !enabled {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _, _ = d.Update(ctx, "")
		cancel()

		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, _, _ = d.Update(ctx, "")
				cancel()
			case <-d.stopChan:
				return
			}
		}
	}()
}

func (d *DuckDNSManager) Stop() {
	close(d.stopChan)
}

func (d *DuckDNSManager) SetCredentials(domain, token string) (bool, string, error) {
	d.mu.Lock()
	d.domain = cleanDuckDomain(domain)
	d.token = strings.TrimSpace(token)
	d.status.Enabled = d.domain != "" && d.token != ""
	d.status.Domain = d.domain
	d.status.FullDomain = formatFullDomain(d.domain)
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return d.Update(ctx, "")
}

func (d *DuckDNSManager) GetStatus() DuckDNSStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.status
}
