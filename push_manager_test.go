package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
