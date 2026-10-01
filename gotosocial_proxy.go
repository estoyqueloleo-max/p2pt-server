package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GoToSocialManager handles reverse proxying, health checking and configuration for GoToSocial
type GoToSocialManager struct {
	cfg          *Config
	targetURL    *url.URL
	reverseProxy *httputil.ReverseProxy
	httpClient   *http.Client
	mu           sync.RWMutex
}

// GoToSocialStatus represents the health and federation state of GoToSocial
type GoToSocialStatus struct {
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Target    string `json:"target"`
	Domain    string `json:"domain"`
	Version   string `json:"version,omitempty"`
	Message   string `json:"message"`
	Fediverse string `json:"fediverse_url"`
}

// NewGoToSocialManager initializes the GoToSocial proxy manager
func NewGoToSocialManager(cfg *Config) (*GoToSocialManager, error) {
	targetRaw := cfg.MastodonTarget
	if targetRaw == "" {
		targetRaw = "http://127.0.0.1:8080"
	}

	targetURL, err := url.Parse(targetRaw)
	if err != nil {
		return nil, fmt.Errorf("URL objetivo de GoToSocial inválida (%s): %w", targetRaw, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Set proper forwarding headers for ActivityPub & Mastodon Client API
		publicHost := cfg.GetPublicIP()
		proto := "http"
		if cfg.EnableTLS {
			proto = "https"
		}

		req.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", publicHost)
		req.Header.Set("X-Forwarded-Proto", proto)

		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			clientIP = req.RemoteAddr
		}
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[GoToSocial] ⚠️ Error proxying request %s: %v", r.URL.Path, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "GoToSocial Unavailable",
			"message": "El nodo Mastodon/GoToSocial local no está respondiendo en " + targetRaw + ". Comprueba que el servicio OpenRC 'gotosocial' esté activo.",
		})
	}

	mgr := &GoToSocialManager{
		cfg:          cfg,
		targetURL:    targetURL,
		reverseProxy: proxy,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}

	return mgr, nil
}

// IsGoToSocialRoute checks if an incoming HTTP path belongs to ActivityPub / Mastodon API
func (m *GoToSocialManager) IsGoToSocialRoute(path string) bool {
	// Standard ActivityPub Discovery
	if strings.HasPrefix(path, "/.well-known/webfinger") ||
		strings.HasPrefix(path, "/.well-known/nodeinfo") ||
		strings.HasPrefix(path, "/.well-known/host-meta") {
		return true
	}

	// Mastodon Client API (v1 / v2) and OAuth
	if strings.HasPrefix(path, "/api/v1/") ||
		strings.HasPrefix(path, "/api/v2/") ||
		strings.HasPrefix(path, "/oauth/") {
		return true
	}

	// ActivityPub actors, inboxes, web profiles
	if strings.HasPrefix(path, "/users/") ||
		strings.HasPrefix(path, "/@") ||
		strings.HasPrefix(path, "/nodeinfo/") ||
		strings.HasPrefix(path, "/inbox") ||
		strings.HasPrefix(path, "/outbox") {
		return true
	}

	return false
}

// ServeHTTP delegates request to GoToSocial reverse proxy
func (m *GoToSocialManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.reverseProxy.ServeHTTP(w, r)
}

// GetStatus checks GoToSocial health and returns its runtime status
func (m *GoToSocialManager) GetStatus(ctx context.Context) GoToSocialStatus {
	publicHost := m.cfg.GetPublicIP()
	proto := "http"
	if m.cfg.EnableTLS {
		proto = "https"
	}
	fedURL := fmt.Sprintf("%s://%s", proto, publicHost)

	status := GoToSocialStatus{
		Enabled:   m.cfg.EnableMastodon,
		Target:    m.targetURL.String(),
		Domain:    publicHost,
		Fediverse: fedURL,
	}

	if !m.cfg.EnableMastodon {
		status.Message = "Nodo Mastodon / GoToSocial desactivado en configuración."
		return status
	}

	// Query nodeinfo or instance API
	checkURL := fmt.Sprintf("%s/api/v1/instance", m.targetURL.String())
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		status.Running = false
		status.Message = fmt.Sprintf("Error creando petición: %v", err)
		return status
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		status.Running = false
		status.Message = fmt.Sprintf("Nodo GoToSocial offline en %s: %v", m.targetURL.String(), err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var instanceData struct {
			Version string `json:"version"`
			Title   string `json:"title"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&instanceData); err == nil {
			status.Version = instanceData.Version
		}
		status.Running = true
		status.Message = fmt.Sprintf("Nodo Mastodon activo y federando en %s (GoToSocial %s)", publicHost, status.Version)
	} else {
		status.Running = false
		status.Message = fmt.Sprintf("GoToSocial respondió con código HTTP %d", resp.StatusCode)
	}

	return status
}

// EnsureGoToSocialConfigFile auto-generates a low-footprint config.yaml suitable for Raspberry Pi / Alpine
func EnsureGoToSocialConfigFile(cfg *Config, targetPath string) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("fallo creando directorio %s: %w", dir, err)
	}

	// Only create if not present to avoid overwriting user edits
	if _, err := os.Stat(targetPath); err == nil {
		return nil
	}

	publicHost := cfg.GetPublicIP()
	if cfg.HTTPPort > 0 && cfg.HTTPPort != 80 && cfg.HTTPPort != 443 && !strings.Contains(publicHost, ":") {
		publicHost = fmt.Sprintf("%s:%d", publicHost, cfg.HTTPPort)
	}
	proto := "http"
	if cfg.EnableTLS {
		proto = "https"
	}
	port := 8080

	content := fmt.Sprintf(`############################################################
# GoToSocial Configuration - Appliance Low-Memory Profile
############################################################

# Host for Fediverse identification
host: "%s"

# Protocol for public URLs
protocol: "%s"

# Network Binding (Internal only, reverse proxied by p2pt-server)
bind-address: "127.0.0.1"
port: %d

trusted-proxies:
  - "127.0.0.1/32"
  - "::1"

# Database (Lightweight SQLite for embedded / RPi)
db-type: "sqlite"
db-address: "/mnt/data/gotosocial/database.sqlite"

# Media Storage
storage-backend: "local"
storage-local-base-path: "/mnt/data/gotosocial/storage"

# Web Assets and Templates
web-template-base-dir: "/mnt/data/gotosocial/web/template/"
web-asset-base-dir: "/mnt/data/gotosocial/web/assets/"

# Aggressive cache eviction to preserve Raspberry Pi SD card space
media-remote-cache-duration: "48h"
media-local-max-size: "10MiB"
media-remote-max-size: "10MiB"

# Application Performance Tuning for Low RAM
advanced-rate-limit-requests: 150
instance-expose-peers: true
instance-federation-mode: "blocklist"

# Accounts
accounts-registration-open: false
log-level: "info"
`, publicHost, proto, port)

	if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("error escribiendo %s: %w", targetPath, err)
	}

	log.Printf("[GoToSocial] 📄 Configuración generada automáticamente en %s para dominio %s", targetPath, publicHost)
	return nil
}
