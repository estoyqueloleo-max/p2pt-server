package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPI_StatusAndTurnCredentials(t *testing.T) {
	cfg := &Config{
		HTTPPort:         9000,
		TURNPort:         3478,
		PublicIP:         "127.0.0.1",
		TopicID:          "test-amigos-valencia",
		AuthSecret:       "test-secret",
		EnableMDNS:       true,
		EnableAutoUpdate: false,
	}

	sigServer := NewSignalingServer(cfg)
	tracker := NewWebTorrentTracker()

	mux := http.NewServeMux()

	// 1. Status handler
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]interface{}{
			"status":         "ok",
			"version":        CurrentVersion,
			"topic_id":       cfg.TopicID,
			"info_hash":      DeriveInfoHash(cfg.TopicID),
			"active_clients": sigServer.ClientCount(),
			"tracker_swarms": tracker.SwarmCount(),
		}
		_ = json.NewEncoder(w).Encode(status)
	})

	// 2. TURN credentials handler
	mux.HandleFunc("/turn-credentials", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"iceServers": []map[string]interface{}{
				{
					"urls":       []string{"turn:127.0.0.1:3478?transport=udp"},
					"username":   "test-user",
					"credential": "test-password",
				},
			},
			"ttl": 86400,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Test GET /status
	reqStatus := httptest.NewRequest("GET", "/status", nil)
	wStatus := httptest.NewRecorder()
	mux.ServeHTTP(wStatus, reqStatus)

	if wStatus.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", wStatus.Code)
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(wStatus.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("Failed to parse /status JSON: %v", err)
	}
	if statusResp["topic_id"] != "test-amigos-valencia" {
		t.Errorf("Expected topic_id 'test-amigos-valencia', got %v", statusResp["topic_id"])
	}
	t.Logf("✅ /status endpoint verified: %+v", statusResp)

	// Test GET /turn-credentials
	reqTurn := httptest.NewRequest("GET", "/turn-credentials", nil)
	wTurn := httptest.NewRecorder()
	mux.ServeHTTP(wTurn, reqTurn)

	if wTurn.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", wTurn.Code)
	}
	var turnResp map[string]interface{}
	if err := json.Unmarshal(wTurn.Body.Bytes(), &turnResp); err != nil {
		t.Fatalf("Failed to parse /turn-credentials JSON: %v", err)
	}
	if _, exists := turnResp["iceServers"]; !exists {
		t.Errorf("Missing iceServers in response: %+v", turnResp)
	}
	t.Logf("✅ /turn-credentials endpoint verified: %+v", turnResp)
}

func TestAPI_ConfigPersistence(t *testing.T) {
	tempEnv := "./test_pingo.env"
	defer os.Remove(tempEnv)

	t.Setenv("PINGO_CONFIG_PATH", tempEnv)

	cfg := &Config{
		HTTPPort:   9000,
		TURNPort:   3478,
		PublicIP:   "test-node.duckdns.org",
		TopicID:    "amigos-valencia",
		DuckDomain: "test-node",
		DuckToken:  "test-token",
		EnableUPnP: true,
	}

	if err := SaveConfigToEnv(cfg); err != nil {
		t.Fatalf("Failed to save config to env: %v", err)
	}

	content, err := os.ReadFile(tempEnv)
	if err != nil {
		t.Fatalf("Failed to read saved env file: %v", err)
	}

	if !bytes.Contains(content, []byte("TOPIC_ID=amigos-valencia")) {
		t.Errorf("Saved env file does not contain TOPIC_ID: %s", string(content))
	}
	t.Log("✅ Config persistence to .env verified successfully!")
}

func TestAPI_WebFrontendServing(t *testing.T) {
	// Create mock web dist dir
	tmpDir, err := os.MkdirTemp("", "pingo_web_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	indexPath := filepath.Join(tmpDir, "index.html")
	if err := os.WriteFile(indexPath, []byte("<html><body><h1>Pingo Sovereign Web</h1></body></html>"), 0644); err != nil {
		t.Fatalf("Failed to write mock index.html: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(tmpDir, "assets"), 0755)
	assetPath := filepath.Join(tmpDir, "assets", "app.js")
	if err := os.WriteFile(assetPath, []byte("console.log('pingo')"), 0644); err != nil {
		t.Fatalf("Failed to write mock app.js: %v", err)
	}

	cfg := &Config{
		HTTPPort: 9000,
		TURNPort: 3478,
		PublicIP: "pingo.appliance.local",
		WebDir:   tmpDir,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/c/") {
			token := strings.TrimPrefix(path, "/c/")
			if data, ok := getShortPairURL(token); ok {
				if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(data.ConfigJSON))
					return
				}
				http.Redirect(w, r, data.FullURL, http.StatusFound)
				return
			}
			http.NotFound(w, r)
			return
		}
		if path == "/web" {
			target := "/web/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(path, "/web/") || strings.HasPrefix(path, "/assets/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			var subPath string
			if strings.HasPrefix(path, "/assets/") {
				subPath = strings.TrimPrefix(path, "/")
			} else {
				subPath = strings.TrimPrefix(path, "/web/")
			}
			subPath = strings.TrimPrefix(subPath, "/")
			if subPath == "" {
				subPath = "index.html"
			}
			targetFile := filepath.Join(cfg.WebDir, subPath)
			if info, err := os.Stat(targetFile); err == nil && !info.IsDir() {
				http.ServeFile(w, r, targetFile)
				return
			}
			if strings.HasPrefix(path, "/web/") {
				fallbackIndex := filepath.Join(cfg.WebDir, "index.html")
				if _, err := os.Stat(fallbackIndex); err == nil {
					http.ServeFile(w, r, fallbackIndex)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Test 1: GET /web redirects with 301 to /web/
	req := httptest.NewRequest("GET", "/web", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected 301 redirect for /web, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/web/" {
		t.Fatalf("Expected Location /web/, got '%s'", rec.Header().Get("Location"))
	}

	// Test 1b: GET /web/ returns index.html
	reqSlash := httptest.NewRequest("GET", "/web/", nil)
	recSlash := httptest.NewRecorder()
	mux.ServeHTTP(recSlash, reqSlash)

	if recSlash.Code != http.StatusOK {
		t.Fatalf("Expected 200 for /web/, got %d", recSlash.Code)
	}
	if !strings.Contains(recSlash.Body.String(), "Pingo Sovereign Web") {
		t.Fatalf("Expected body to contain 'Pingo Sovereign Web', got '%s'", recSlash.Body.String())
	}

	// Test 1c: GET /assets/app.js resolves correctly
	reqAssets := httptest.NewRequest("GET", "/assets/app.js", nil)
	recAssets := httptest.NewRecorder()
	mux.ServeHTTP(recAssets, reqAssets)
	if recAssets.Code != http.StatusOK || !strings.Contains(recAssets.Body.String(), "console.log('pingo')") {
		t.Fatalf("Expected 200 and asset content for /assets/app.js, got %d", recAssets.Code)
	}

	// Test 2: SPA deep link /web/room/123
	reqSPA := httptest.NewRequest("GET", "/web/room/123", nil)
	recSPA := httptest.NewRecorder()
	mux.ServeHTTP(recSPA, reqSPA)

	if recSPA.Code != http.StatusOK {
		t.Fatalf("Expected 200 for SPA deep route, got %d", recSPA.Code)
	}
	if !strings.Contains(recSPA.Body.String(), "Pingo Sovereign Web") {
		t.Fatalf("Expected SPA fallback to serve index.html")
	}

	// Test 3: generatePairConfig uses /web URL and generates short URL
	_, configJSONBytes, pairURL, shortPairURL := generatePairConfig(cfg)
	if !strings.Contains(pairURL, "http://pingo.appliance.local:9000/web/?serverConfig=") {
		t.Errorf("Expected pairURL to point to appliance /web, got: %s", pairURL)
	}
	if !strings.Contains(shortPairURL, "http://pingo.appliance.local:9000/c/") {
		t.Errorf("Expected shortPairURL to point to /c/{token}, got: %s", shortPairURL)
	}

	// Test 4: Short URL redirect /c/{token} -> 302 Found to full pairURL
	tokenParts := strings.Split(shortPairURL, "/c/")
	if len(tokenParts) != 2 {
		t.Fatalf("Invalid shortPairURL format: %s", shortPairURL)
	}
	shortToken := tokenParts[1]

	reqShort := httptest.NewRequest("GET", "/c/"+shortToken, nil)
	recShort := httptest.NewRecorder()
	mux.ServeHTTP(recShort, reqShort)

	if recShort.Code != http.StatusFound {
		t.Fatalf("Expected 302 Found for /c/%s, got %d", shortToken, recShort.Code)
	}
	if loc := recShort.Header().Get("Location"); loc != pairURL {
		t.Errorf("Expected Location header %s, got %s", pairURL, loc)
	}

	// Test 5: Short URL with format=json returns raw configuration JSON
	reqJSON := httptest.NewRequest("GET", "/c/"+shortToken+"?format=json", nil)
	recJSON := httptest.NewRecorder()
	mux.ServeHTTP(recJSON, reqJSON)

	if recJSON.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /c/%s?format=json, got %d", shortToken, recJSON.Code)
	}
	if recJSON.Body.String() != configJSONBytes {
		t.Errorf("Expected body to match configJSONBytes")
	}

	t.Logf("✅ Web frontend serving & Sovereign pairURL verified: %s", pairURL)
	t.Logf("✅ Short URL & Redirect verified: %s -> %s", shortPairURL, pairURL)
}
