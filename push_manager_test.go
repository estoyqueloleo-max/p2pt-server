package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPushManager_Subscribe(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "push_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPushManager(tmpDir)

	payload := map[string]interface{}{
		"userPublicKey": "12345678",
		"salt":          "test-salt",
		"endpoint":      "https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB...",
		"keys": map[string]string{
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9t0AgtukVEqwcWAiiYz5mfzv4Wqx6VNvBAKYWY0WA==",
			"auth":   "tBHItJI5svbpez7KI4CCXg==",
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/push/subscribe", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	pm.HandleSubscribe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if rec.Body.String() != "Cloud activated" {
		t.Errorf("Expected 'Cloud activated', got '%s'", rec.Body.String())
	}

	// Verificar persistencia en memoria y mapa
	pm.mu.RLock()
	record, exists := pm.records["12345678"]
	pm.mu.RUnlock()

	if !exists {
		t.Fatalf("Expected peer 12345678 to be registered in PushManager")
	}
	if record.Salt != "test-salt" {
		t.Errorf("Expected salt 'test-salt', got '%s'", record.Salt)
	}
}

func TestPushManager_VAPIDKeysAutoGeneration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "push_vapid_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Inicializar primer PushManager sin env vars
	pm1 := NewPushManager(tmpDir)
	pub1 := pm1.GetVAPIDPublicKey()
	if pub1 == "" {
		t.Fatalf("Expected non-empty VAPID public key")
	}

	// Segundo PushManager apuntando al mismo directorio debe cargar las mismas claves persistidas
	pm2 := NewPushManager(tmpDir)
	pub2 := pm2.GetVAPIDPublicKey()

	if pub1 != pub2 {
		t.Errorf("Expected persisted VAPID key to match across reloads: %s vs %s", pub1, pub2)
	}
}

func TestPushManager_VAPIDEndpoint(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "push_endpoint_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPushManager(tmpDir)
	req := httptest.NewRequest(http.MethodGet, "/push/vapid-public-key", nil)
	rec := httptest.NewRecorder()

	pm.HandleVAPIDPublicKey(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if resp["vapidPublicKey"] != pm.GetVAPIDPublicKey() {
		t.Errorf("Expected VAPID key %s, got %s", pm.GetVAPIDPublicKey(), resp["vapidPublicKey"])
	}
}

func TestPushManager_SendWithAuth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "push_send_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPushManager(tmpDir)

	// Mock push service (RFC 8291 / 8292 endpoint)
	var receivedAuthHeader string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer mockServer.Close()

	// Generate valid P-256 client keys for subscription
	curve := elliptic.P256()
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	pubBytes := elliptic.Marshal(curve, x, y)
	p256dh := base64.RawURLEncoding.EncodeToString(pubBytes)
	authBytes := make([]byte, 16)
	_, _ = rand.Read(authBytes)
	authSecret := base64.RawURLEncoding.EncodeToString(authBytes)

	// Register Bob (target)
	bobSub := map[string]interface{}{
		"userPublicKey": "bob-123",
		"salt":          "bob-salt",
		"endpoint":      mockServer.URL,
		"keys": map[string]string{
			"p256dh": p256dh,
			"auth":   authSecret,
		},
	}
	subBody, _ := json.Marshal(bobSub)
	subReq := httptest.NewRequest(http.MethodPost, "/push/subscribe", bytes.NewReader(subBody))
	subRec := httptest.NewRecorder()
	pm.HandleSubscribe(subRec, subReq)
	if subRec.Code != http.StatusOK {
		t.Fatalf("Subscribe failed: %d", subRec.Code)
	}

	// Register Alice (sender)
	aliceSub := map[string]interface{}{
		"userPublicKey": "alice-456",
		"salt":          "alice-salt",
		"endpoint":      mockServer.URL,
		"keys": map[string]string{
			"p256dh": p256dh,
			"auth":   authSecret,
		},
	}
	aliceSubBody, _ := json.Marshal(aliceSub)
	aliceSubReq := httptest.NewRequest(http.MethodPost, "/push/subscribe", bytes.NewReader(aliceSubBody))
	pm.HandleSubscribe(httptest.NewRecorder(), aliceSubReq)

	// Alice sends push to Bob with valid X-Pingo-Auth
	token := generatePingoAuthToken("alice-salt")
	sendPayload := map[string]string{
		"title": "Ping de Alice",
		"body":  "Hola Bob",
	}
	sendBytes, _ := json.Marshal(sendPayload)
	sendReq := httptest.NewRequest(http.MethodPost, "/push/send/bob-123?from=alice-456", bytes.NewReader(sendBytes))
	sendReq.Header.Set("X-Pingo-Auth", token)
	sendRec := httptest.NewRecorder()

	pm.HandleSend(sendRec, sendReq)

	if sendRec.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created from push service, got %d: %s", sendRec.Code, sendRec.Body.String())
	}

	if !strings.HasPrefix(receivedAuthHeader, "vapid ") {
		t.Errorf("Expected 'vapid ' Authorization header, got: %s", receivedAuthHeader)
	}
}

func TestPushManager_PruneDeadSubscription(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "push_prune_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pm := NewPushManager(tmpDir)

	// Mock push service returning 410 Gone (expired subscription)
	mockPruneServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer mockPruneServer.Close()

	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	pubBytes := elliptic.Marshal(curve, x, y)
	p256dh := base64.RawURLEncoding.EncodeToString(pubBytes)
	authBytes := make([]byte, 16)
	_, _ = rand.Read(authBytes)
	authSecret := base64.RawURLEncoding.EncodeToString(authBytes)

	// Register Charlie
	charlieSub := map[string]interface{}{
		"userPublicKey": "charlie-789",
		"salt":          "charlie-salt",
		"endpoint":      mockPruneServer.URL,
		"keys": map[string]string{
			"p256dh": p256dh,
			"auth":   authSecret,
		},
	}
	b, _ := json.Marshal(charlieSub)
	pm.HandleSubscribe(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/push/subscribe", bytes.NewReader(b)))

	if pm.GetSubscriptionsCount() != 1 {
		t.Fatalf("Expected 1 subscription before test, got %d", pm.GetSubscriptionsCount())
	}

	// Trigger push to Charlie
	testReq := httptest.NewRequest(http.MethodGet, "/push/test/charlie-789", nil)
	testRec := httptest.NewRecorder()
	pm.HandleTest(testRec, testReq)

	// Charlie should now be pruned
	if pm.GetSubscriptionsCount() != 0 {
		t.Errorf("Expected 0 subscriptions after 410 Gone, but found %d", pm.GetSubscriptionsCount())
	}
}
