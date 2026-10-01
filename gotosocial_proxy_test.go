package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoToSocial_IsGoToSocialRoute(t *testing.T) {
	cfg := &Config{
		PublicIP:       "test.duckdns.org",
		EnableMastodon: true,
	}
	mgr, err := NewGoToSocialManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create GoToSocialManager: %v", err)
	}

	validRoutes := []string{
		"/.well-known/webfinger?resource=acct:user@test.duckdns.org",
		"/.well-known/nodeinfo",
		"/.well-known/host-meta",
		"/api/v1/instance",
		"/api/v1/apps",
		"/api/v2/search",
		"/oauth/token",
		"/auth/sign_in",
		"/auth/sign_out",
		"/assets/dist/app.css",
		"/users/jose",
		"/users/jose/inbox",
		"/@jose",
		"/nodeinfo/2.0",
		"/inbox",
		"/outbox",
	}

	for _, route := range validRoutes {
		if !mgr.IsGoToSocialRoute(route) {
			t.Errorf("Expected route '%s' to be matched as GoToSocial route, but was rejected", route)
		}
	}

	invalidRoutes := []string{
		"/tracker",
		"/peerjs/id",
		"/api/status",
		"/api/git/repos",
		"/git/user/routes.git",
		"/api/auth/login",
		"/api/wifi/scan",
	}

	for _, route := range invalidRoutes {
		if mgr.IsGoToSocialRoute(route) {
			t.Errorf("Expected route '%s' NOT to be matched as GoToSocial route, but was matched", route)
		}
	}
}

func TestGoToSocial_ReverseProxyForwarding(t *testing.T) {
	// Mock local GoToSocial backend
	var receivedHost, receivedForwardedHost, receivedProto string
	mockGTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedForwardedHost = r.Header.Get("X-Forwarded-Host")
		receivedProto = r.Header.Get("X-Forwarded-Proto")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"uri":    "mock.duckdns.org",
		})
	}))
	defer mockGTS.Close()

	cfg := &Config{
		PublicIP:       "mock.duckdns.org",
		EnableTLS:      true,
		EnableMastodon: true,
		MastodonTarget: mockGTS.URL,
	}

	mgr, err := NewGoToSocialManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create GoToSocialManager: %v", err)
	}

	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:user@mock.duckdns.org", nil)
	w := httptest.NewRecorder()

	mgr.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK from reverse proxy, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Errorf("Expected response body from mock GoToSocial")
	}

	if receivedForwardedHost != "mock.duckdns.org" {
		t.Errorf("Expected X-Forwarded-Host 'mock.duckdns.org', got '%s'", receivedForwardedHost)
	}
	if receivedProto != "https" {
		t.Errorf("Expected X-Forwarded-Proto 'https', got '%s'", receivedProto)
	}
	if receivedHost == "" {
		t.Errorf("Expected Host to be preserved")
	}
}

func TestGoToSocial_GenerateConfigYAML(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gts-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		PublicIP: "test-node.duckdns.org",
	}

	targetConfig := filepath.Join(tempDir, "config.yaml")
	if err := EnsureGoToSocialConfigFile(cfg, targetConfig); err != nil {
		t.Fatalf("EnsureGoToSocialConfigFile failed: %v", err)
	}

	data, err := os.ReadFile(targetConfig)
	if err != nil {
		t.Fatalf("Failed to read created config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, `host: "test-node.duckdns.org"`) {
		t.Errorf("Expected host to be set to 'test-node.duckdns.org'")
	}
	if !strings.Contains(content, `db-type: "sqlite"`) {
		t.Errorf("Expected db-type to be sqlite")
	}
}

func TestGoToSocial_HealthStatus(t *testing.T) {
	// Mock running GoToSocial
	mockGTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/instance" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"title":   "Mi Nodo Appliance",
				"version": "0.17.0",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockGTS.Close()

	cfg := &Config{
		PublicIP:       "my-appliance.duckdns.org",
		EnableMastodon: true,
		MastodonTarget: mockGTS.URL,
	}

	mgr, err := NewGoToSocialManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create GoToSocialManager: %v", err)
	}

	status := mgr.GetStatus(context.Background())
	if !status.Running {
		t.Errorf("Expected GoToSocial to be reported as running, message: %s", status.Message)
	}
	if status.Version != "0.17.0" {
		t.Errorf("Expected version '0.17.0', got '%s'", status.Version)
	}
}
