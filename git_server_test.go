//go:build !windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestGitToken_GenerateAndValidate(t *testing.T) {
	secret := "test-secret-12345"
	peerID := "pingo-peer-alpha"
	expiry := time.Now().Add(1 * time.Hour)

	token := GenerateGitToken(secret, peerID, expiry)
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// 1. Valid token
	if !ValidateGitToken(secret, peerID, token) {
		t.Error("Expected token to be valid for matching peerID and unexpired time")
	}

	// 2. Wrong peerID
	if ValidateGitToken(secret, "pingo-peer-beta", token) {
		t.Error("Expected validation to fail for a different peerID")
	}

	// 3. Wrong secret
	if ValidateGitToken("wrong-secret", peerID, token) {
		t.Error("Expected validation to fail with wrong secret")
	}

	// 4. Expired token
	pastExpiry := time.Now().Add(-1 * time.Minute)
	expiredToken := GenerateGitToken(secret, peerID, pastExpiry)
	if ValidateGitToken(secret, peerID, expiredToken) {
		t.Error("Expected expired token to be rejected")
	}
}

func TestGitServer_CredentialsAndPeerIsolation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-peer-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		Username:   "admin",
		Password:   "admin-pass",
		AuthSecret: "super-turn-git-secret",
		GitDir:     tempDir,
		HTTPPort:   9000,
	}
	authMgr := NewAuthManager("admin-pass", true)

	server, err := NewGitServer(cfg, authMgr)
	if err != nil {
		t.Fatalf("Failed to create GitServer: %v", err)
	}

	// 1. Request credentials for peer-1
	reqCreds := httptest.NewRequest("GET", "/git-credentials?peerId=pingo-peer-1", nil)
	wCreds := httptest.NewRecorder()
	server.HandleGitCredentials(wCreds, reqCreds)

	if wCreds.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for /git-credentials, got %d", wCreds.Code)
	}

	var credsResp struct {
		Enabled  bool   `json:"enabled"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(wCreds.Body).Decode(&credsResp); err != nil {
		t.Fatalf("Failed to parse /git-credentials response: %v", err)
	}

	if credsResp.Username != "pingo-peer-1" {
		t.Errorf("Expected username 'pingo-peer-1', got '%s'", credsResp.Username)
	}
	if credsResp.Token == "" {
		t.Fatal("Expected token in response")
	}

	// 2. Re-requesting credentials anonymously for already claimed peer MUST be rejected (409 Conflict)
	reqReclaim := httptest.NewRequest("GET", "/git-credentials?peerId=pingo-peer-1", nil)
	wReclaim := httptest.NewRecorder()
	server.HandleGitCredentials(wReclaim, reqReclaim)
	if wReclaim.Code != http.StatusConflict {
		t.Errorf("Expected status 409 Conflict when re-requesting claimed peer, got %d", wReclaim.Code)
	}

	// 3. Re-requesting credentials providing current token MUST succeed (owner refresh)
	reqRefresh := httptest.NewRequest("GET", "/git-credentials?peerId=pingo-peer-1&token="+credsResp.Token, nil)
	wRefresh := httptest.NewRecorder()
	server.HandleGitCredentials(wRefresh, reqRefresh)
	if wRefresh.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK when owner refreshes credentials with valid token, got %d", wRefresh.Code)
	}
	var refreshResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(wRefresh.Body).Decode(&refreshResp)
	credsResp.Token = refreshResp.Token

	// 4. Peer-1 accesses their own repository: should succeed and create bare repo JIT
	reqOwn := httptest.NewRequest("GET", "/git/pingo-peer-1/routes.git/info/refs?service=git-upload-pack", nil)
	basicAuthOwn := "Basic " + base64.StdEncoding.EncodeToString([]byte(credsResp.Username+":"+credsResp.Token))
	reqOwn.Header.Set("Authorization", basicAuthOwn)
	wOwn := httptest.NewRecorder()
	server.ServeHTTP(wOwn, reqOwn)

	if wOwn.Code != http.StatusOK {
		t.Fatalf("Expected status 200 OK for peer accessing own repo with HMAC token, got %d", wOwn.Code)
	}

	// 5. Peer-1 tries to access Peer-2's repository: should be denied (401 Unauthorized isolation)
	reqOther := httptest.NewRequest("GET", "/git/pingo-peer-2/routes.git/info/refs?service=git-upload-pack", nil)
	reqOther.Header.Set("Authorization", basicAuthOwn)
	wOther := httptest.NewRecorder()
	server.ServeHTTP(wOther, reqOther)

	if wOther.Code != http.StatusUnauthorized {
		t.Errorf("Expected isolation to block peer-1 from peer-2 repo (401), got %d", wOther.Code)
	}

	// 6. Revocation test: revoke peer-1
	server.RevokePeer("pingo-peer-1")
	if !server.IsPeerRevoked("pingo-peer-1") {
		t.Error("Expected pingo-peer-1 to be marked as revoked")
	}

	// Requesting credentials should now return 403 Forbidden
	reqRevokedCreds := httptest.NewRequest("GET", "/git-credentials?peerId=pingo-peer-1", nil)
	wRevokedCreds := httptest.NewRecorder()
	server.HandleGitCredentials(wRevokedCreds, reqRevokedCreds)
	if wRevokedCreds.Code != http.StatusForbidden {
		t.Errorf("Expected /git-credentials to return 403 for revoked peer, got %d", wRevokedCreds.Code)
	}

	// Access to own repository should now be denied
	wRevokedAccess := httptest.NewRecorder()
	server.ServeHTTP(wRevokedAccess, reqOwn)
	if wRevokedAccess.Code != http.StatusUnauthorized {
		t.Errorf("Expected revoked peer to be denied git access (401), got %d", wRevokedAccess.Code)
	}

	// 7. Unrevoke test: restore access
	server.UnrevokePeer("pingo-peer-1")
	if server.IsPeerRevoked("pingo-peer-1") {
		t.Error("Expected pingo-peer-1 to no longer be revoked")
	}

	wRestoredAccess := httptest.NewRecorder()
	server.ServeHTTP(wRestoredAccess, reqOwn)
	if wRestoredAccess.Code != http.StatusOK {
		t.Errorf("Expected restored access for unrevoked peer, got %d", wRestoredAccess.Code)
	}

	// 8. Admin unlocks peer-1 claim to transfer/bind to a new device
	server.UnlockPeerClaim("pingo-peer-1")
	if server.GetPeerClaim("pingo-peer-1") != nil {
		t.Error("Expected pingo-peer-1 claim to be unlocked")
	}

	// New device now claims pingo-peer-1
	reqNewDevice := httptest.NewRequest("GET", "/git-credentials?peerId=pingo-peer-1", nil)
	wNewDevice := httptest.NewRecorder()
	server.HandleGitCredentials(wNewDevice, reqNewDevice)
	if wNewDevice.Code != http.StatusOK {
		t.Fatalf("Expected new device to successfully claim unlocked peer-1, got %d", wNewDevice.Code)
	}

	var newCredsResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(wNewDevice.Body).Decode(&newCredsResp)

	// Old token should now be rejected because active device claim was rotated
	wOldTokenAccess := httptest.NewRecorder()
	server.ServeHTTP(wOldTokenAccess, reqOwn)
	if wOldTokenAccess.Code != http.StatusUnauthorized {
		t.Errorf("Expected old token to be rejected after claim rotation (401), got %d", wOldTokenAccess.Code)
	}

	// New token should work
	reqNewToken := httptest.NewRequest("GET", "/git/pingo-peer-1/routes.git/info/refs?service=git-upload-pack", nil)
	reqNewToken.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("pingo-peer-1:"+newCredsResp.Token)))
	wNewTokenAccess := httptest.NewRecorder()
	server.ServeHTTP(wNewTokenAccess, reqNewToken)
	if wNewTokenAccess.Code != http.StatusOK {
		t.Errorf("Expected new token to be accepted, got %d", wNewTokenAccess.Code)
	}
}

