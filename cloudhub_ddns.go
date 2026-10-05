package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudHubDDNSStatus almacena el estado de sincronización con el Cloud Hub (klitosan.com)
type CloudHubDDNSStatus struct {
	Enabled      bool      `json:"enabled"`
	ApplianceID  string    `json:"appliance_id"`
	Subdomain    string    `json:"subdomain"`
	HubEndpoint  string    `json:"hub_endpoint"`
	LastUpdate   time.Time `json:"last_update,omitempty"`
	LastSuccess  bool      `json:"last_success"`
	LastMessage  string    `json:"last_message"`
	CurrentIP    string    `json:"current_ip,omitempty"`
	ECHReady     bool      `json:"ech_ready"`
}

// CloudHubDDNSManager gestiona el latido y registro dinámico con el Cloudflare Worker Gateway
type CloudHubDDNSManager struct {
	mu           sync.RWMutex
	applianceID  string
	secretToken  string
	hubEndpoint  string
	interval     time.Duration
	status       CloudHubDDNSStatus
	stopChan     chan struct{}
	onUpdateFunc func(subdomain, currentIP string)
}

func NewCloudHubDDNSManager(applianceID, secretToken, hubEndpoint string, onUpdate func(subdomain, currentIP string)) *CloudHubDDNSManager {
	if hubEndpoint == "" {
		hubEndpoint = "https://pingo-cloud.accreativos.com"
	}
	hubEndpoint = strings.TrimRight(hubEndpoint, "/")

	mgr := &CloudHubDDNSManager{
		applianceID:  strings.TrimSpace(applianceID),
		secretToken:  strings.TrimSpace(secretToken),
		hubEndpoint:  hubEndpoint,
		interval:     10 * time.Minute,
		onUpdateFunc: onUpdate,
		stopChan:     make(chan struct{}),
	}

	mgr.status = CloudHubDDNSStatus{
		Enabled:     mgr.applianceID != "" && mgr.secretToken != "",
		ApplianceID: mgr.applianceID,
		HubEndpoint: mgr.hubEndpoint,
		LastMessage: "No inicializado",
	}

	return mgr
}

// Update envía el latido al Cloud Hub para refrescar la IP pública en Cloudflare DNS con protección de cuota
func (c *CloudHubDDNSManager) Update(ctx context.Context) (bool, string, error) {
	c.mu.Lock()
	id := c.applianceID
	token := c.secretToken
	hub := c.hubEndpoint
	c.mu.Unlock()

	if id == "" || token == "" {
		return false, "ID o Token de Cloud Hub DDNS no configurados", fmt.Errorf("missing credentials")
	}

	url := fmt.Sprintf("%s/api/v1/ddns/heartbeat", hub)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return false, fmt.Sprintf("Error creando petición: %v", err), err
	}

	req.Header.Set("X-Appliance-ID", id)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		msg := fmt.Sprintf("Fallo de conexión con Cloud Hub (%s): %v", hub, err)
		c.setStatus(false, msg, "", "", false)
		return false, msg, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("Error leyendo respuesta de Cloud Hub: %v", err)
		c.setStatus(false, msg, "", "", false)
		return false, msg, err
	}

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("Cloud Hub respondió HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
		c.setStatus(false, msg, "", "", false)
		return false, msg, fmt.Errorf("cloud hub rejected heartbeat: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Status    string `json:"status"`
		IP        string `json:"ip"`
		Subdomain string `json:"subdomain"`
		ECHReady  bool   `json:"echReady"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		msg := fmt.Sprintf("Respuesta inválida de Cloud Hub: %s", string(bodyBytes))
		c.setStatus(false, msg, "", "", false)
		return false, msg, err
	}

	msg := fmt.Sprintf("Cloud Hub DDNS OK [%s] -> %s (%s)", result.Status, result.Subdomain, result.IP)
	c.setStatus(true, msg, result.IP, result.Subdomain, result.ECHReady)

	if c.onUpdateFunc != nil && result.Subdomain != "" {
		c.onUpdateFunc(result.Subdomain, result.IP)
	}

	log.Printf("[CloudHub-DDNS] 🛡️ %s (ECH: %t)", msg, result.ECHReady)
	return true, msg, nil
}

func (c *CloudHubDDNSManager) setStatus(success bool, msg, ip, subdomain string, echReady bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.status.Enabled = c.applianceID != "" && c.secretToken != ""
	c.status.ApplianceID = c.applianceID
	c.status.HubEndpoint = c.hubEndpoint
	c.status.LastUpdate = time.Now()
	c.status.LastSuccess = success
	c.status.LastMessage = msg
	if ip != "" {
		c.status.CurrentIP = ip
	}
	if subdomain != "" {
		c.status.Subdomain = subdomain
	}
	c.status.ECHReady = echReady
}

func (c *CloudHubDDNSManager) GetStatus() CloudHubDDNSStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// StartBackgroundSync lanza el loop de sincronización periódica cada intervalo
func (c *CloudHubDDNSManager) StartBackgroundSync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, _, _ = c.Update(ctx)
		cancel()

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopChan:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				_, _, _ = c.Update(ctx)
				cancel()
			}
		}
	}()
}
