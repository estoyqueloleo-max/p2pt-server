//go:build !windows

package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGitServer_CORS_Preflight(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		Username: "jose",
		Password: "secret-password",
		GitDir:   tempDir,
		HTTPPort: 9000,
	}
	authMgr := NewAuthManager("admin-pass", true)

	server, err := NewGitServer(cfg, authMgr)
	if err != nil {
		t.Fatalf("Failed to create GitServer: %v", err)
	}

	req := httptest.NewRequest("OPTIONS", "/git/jose/pingo.git/info/refs", nil)
	req.Header.Set("Origin", "https://app.pingo.me")
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204 No Content for OPTIONS preflight, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.pingo.me" {
		t.Errorf("Expected Access-Control-Allow-Origin https://app.pingo.me, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("Expected Access-Control-Allow-Methods to be set")
	}
}

func TestGitServer_Unauthorized(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		Username: "jose",
		Password: "secret-password",
		GitDir:   tempDir,
		HTTPPort: 9000,
	}
	authMgr := NewAuthManager("admin-pass", true)

	server, err := NewGitServer(cfg, authMgr)
	if err != nil {
		t.Fatalf("Failed to create GitServer: %v", err)
	}

	req := httptest.NewRequest("GET", "/git/jose/pingo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d", resp.StatusCode)
	}
}

func TestGitServer_UserIsolation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		Username: "jose",
		Password: "secret-password",
		GitDir:   tempDir,
		HTTPPort: 9000,
	}
	authMgr := NewAuthManager("admin-pass", true)

	server, err := NewGitServer(cfg, authMgr)
	if err != nil {
		t.Fatalf("Failed to create GitServer: %v", err)
	}

	// Try to access "maria"'s repo with "jose"'s credentials
	req := httptest.NewRequest("GET", "/git/maria/pingo.git/info/refs?service=git-upload-pack", nil)
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("jose:secret-password"))
	req.Header.Set("Authorization", basicAuth)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected user isolation to reject access with 401 Unauthorized, got %d", resp.StatusCode)
	}
}

func TestGitServer_Authorized_And_JIT_Creation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		Username: "jose",
		Password: "secret-password",
		GitDir:   tempDir,
		HTTPPort: 9000,
	}
	authMgr := NewAuthManager("admin-pass", true)

	server, err := NewGitServer(cfg, authMgr)
	if err != nil {
		t.Fatalf("Failed to create GitServer: %v", err)
	}

	// Request info/refs for user's own repo
	req := httptest.NewRequest("GET", "/git/jose/pingo.git/info/refs?service=git-upload-pack", nil)
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("jose:secret-password"))
	req.Header.Set("Authorization", basicAuth)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	// Verify that bare repo was JIT-created
	repoPath := filepath.Join(tempDir, "jose", "pingo.git")
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Errorf("Expected bare repo to be automatically created at %s", repoPath)
	}
}
