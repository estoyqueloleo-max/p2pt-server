package main

import (
	"context"
	"fmt"
	"io"
	"log"
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
	NextUpdateIn string    `json:"next_update_in,omitempty"`
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

	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s", domain, token, customIP)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, "Error creando petición HTTP", err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		msg := fmt.Sprintf("Error de conexión con DuckDNS: %v", err)
		d.setStatus(false, msg, "")
		return false, msg, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("Error leyendo respuesta de DuckDNS: %v", err)
		d.setStatus(false, msg, "")
		return false, msg, err
	}

	bodyStr := strings.TrimSpace(string(bodyBytes))
	fullDom := formatFullDomain(domain)

	if strings.Contains(bodyStr, "OK") {
		msg := fmt.Sprintf("DuckDNS actualizado correctamente (%s)", fullDom)
		d.setStatus(true, msg, customIP)
		if d.onUpdateFunc != nil {
			d.onUpdateFunc(fullDom, customIP)
		}
		log.Printf("[DuckDNS] ✅ %s", msg)
		return true, msg, nil
	}

	msg := "DuckDNS respondió KO (verifica que el subdominio y el Token sean correctos)"
	d.setStatus(false, msg, "")
	log.Printf("[DuckDNS] ❌ %s", msg)
	return false, msg, fmt.Errorf("duckdns rejected credentials (KO)")
}

func (d *DuckDNSManager) setStatus(success bool, msg, ip string) {
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
}

// StartBackgroundSync starts the periodic update loop
func (d *DuckDNSManager) StartBackgroundSync() {
	d.mu.RLock()
	enabled := d.domain != "" && d.token != ""
	d.mu.RUnlock()

	if !enabled {
		return
	}

	go func() {
		// Run first update immediately
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

// SetCredentials updates the domain/token and triggers an immediate sync
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
