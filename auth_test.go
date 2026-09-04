package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuth_LoginSuccessAndSessionCookie(t *testing.T) {
	authMgr := NewAuthManager("super-secret-password-123", true)

	// 1. Successful Login
	payload := []byte(`{"password":"super-secret-password-123"}`)
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(payload))
	req.RemoteAddr = "192.168.1.100:54321"
	w := httptest.NewRecorder()

	authMgr.HandleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// Verify session cookie was set
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatalf("Expected cookie %s to be set", SessionCookieName)
	}
	if sessionCookie.Value == "" {
		t.Fatalf("Expected non-empty session token")
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("Expected HttpOnly cookie")
	}

	t.Logf("✅ Login successful and secure session cookie issued: %s...", sessionCookie.Value[:12])
}

func TestAuth_InvalidPasswordAndRateLimiting(t *testing.T) {
	authMgr := NewAuthManager("valid-admin-password", true)
	clientIP := "198.51.100.44:12345"

	// 1. Attempt 4 failures
	for i := 1; i <= 4; i++ {
		payload := []byte(`{"password":"wrong-password"}`)
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(payload))
		req.RemoteAddr = clientIP
		w := httptest.NewRecorder()

		authMgr.HandleLogin(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Attempt %d: Expected 401 Unauthorized, got %d", i, w.Code)
		}

		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		expectedRemaining := float64(MaxLoginFailures - i)
		if resp["remaining_attempts"] != expectedRemaining {
			t.Errorf("Expected %v remaining attempts, got %v", expectedRemaining, resp["remaining_attempts"])
		}
	}

	// 2. 5th failure triggers lockout
	{
		payload := []byte(`{"password":"wrong-password"}`)
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(payload))
		req.RemoteAddr = clientIP
		w := httptest.NewRecorder()

		authMgr.HandleLogin(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("5th attempt: Expected 401 Unauthorized, got %d", w.Code)
		}
		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["locked"] != true {
			t.Errorf("Expected locked: true on 5th attempt")
		}
	}

	// 3. 6th attempt should be blocked with 429 Too Many Requests
	{
		payload := []byte(`{"password":"valid-admin-password"}`) // Even with correct password now!
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(payload))
		req.RemoteAddr = clientIP
		w := httptest.NewRecorder()

		authMgr.HandleLogin(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("Expected 429 Too Many Requests during lockout, got %d: %s", w.Code, w.Body.String())
		}
	}

	t.Log("✅ Anti-brute force rate limiting verified: IP blocked after 5 failures.")
}

func TestAuth_ProtectedEndpointsAndBearerToken(t *testing.T) {
	adminPass := "master-key-xyz"
	authMgr := NewAuthManager(adminPass, true)

	protectedHandler := authMgr.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"secret_data": "top-secret"})
	})

	// 1. Unauthorized request
	req1 := httptest.NewRequest("GET", "/api/config", nil)
	w1 := httptest.NewRecorder()
	protectedHandler(w1, req1)

	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized without credentials, got %d", w1.Code)
	}

	// 2. Authorized via Bearer Token (direct admin pass)
	req2 := httptest.NewRequest("GET", "/api/config", nil)
	req2.Header.Set("Authorization", "Bearer "+adminPass)
	w2 := httptest.NewRecorder()
	protectedHandler(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK with Bearer admin pass, got %d", w2.Code)
	}

	// 3. Authorized via Session Cookie
	sess, err := authMgr.CreateSession("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	req3 := httptest.NewRequest("GET", "/api/config", nil)
	req3.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	w3 := httptest.NewRecorder()
	protectedHandler(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK with valid session cookie, got %d", w3.Code)
	}

	t.Log("✅ Endpoint authorization verified for Unauthorized, Bearer Token, and Session Cookie.")
}

func TestAuth_LocalNetworkEnforcement(t *testing.T) {
	adminPass := "test-admin"
	authMgr := NewAuthManager(adminPass, true)

	hardwareHandler := authMgr.RequireAuth(authMgr.RequireLocalNetwork(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"result": "wifi_configured"})
	}))

	// Case A: Valid credentials BUT from Public WAN IP -> MUST BE FORBIDDEN (403)
	reqWAN := httptest.NewRequest("POST", "/api/wifi/configure", nil)
	reqWAN.RemoteAddr = "203.0.113.88:44321" // Public IP
	reqWAN.Header.Set("Authorization", "Bearer "+adminPass)
	wWAN := httptest.NewRecorder()

	hardwareHandler(wWAN, reqWAN)

	if wWAN.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when calling hardware endpoint from WAN IP, got %d: %s", wWAN.Code, wWAN.Body.String())
	}
	t.Logf("✅ Correctly rejected WAN IP from hardware endpoint: %s", wWAN.Body.String())

	// Case B: Valid credentials from Local LAN IP (192.168.1.100) -> Allowed (200)
	reqLAN := httptest.NewRequest("POST", "/api/wifi/configure", nil)
	reqLAN.RemoteAddr = "192.168.1.100:44321" // Private LAN IP
	reqLAN.Header.Set("Authorization", "Bearer "+adminPass)
	wLAN := httptest.NewRecorder()

	hardwareHandler(wLAN, reqLAN)

	if wLAN.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK when calling hardware endpoint from LAN IP, got %d: %s", wLAN.Code, wLAN.Body.String())
	}

	// Case C: Valid credentials from Hotspot Subnet IP (192.168.4.15) -> Allowed (200)
	reqHotspot := httptest.NewRequest("POST", "/api/wifi/configure", nil)
	reqHotspot.RemoteAddr = "192.168.4.15:44321" // Hotspot AP IP
	reqHotspot.Header.Set("Authorization", "Bearer "+adminPass)
	wHotspot := httptest.NewRecorder()

	hardwareHandler(wHotspot, reqHotspot)

	if wHotspot.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK when calling hardware endpoint from Hotspot IP, got %d: %s", wHotspot.Code, wHotspot.Body.String())
	}

	t.Log("✅ Hardware endpoint network isolation verified (LAN/Hotspot allowed, WAN strictly forbidden).")
}

func TestAuth_SessionExpirationAndLogout(t *testing.T) {
	authMgr := NewAuthManager("admin", true)

	sess, err := authMgr.CreateSession("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Artificially expire the session
	authMgr.mu.Lock()
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour)
	authMgr.mu.Unlock()

	req := httptest.NewRequest("GET", "/api/config", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})

	if authMgr.IsAuthenticated(req) {
		t.Fatalf("Expected expired session to be invalid")
	}

	t.Log("✅ Expired session rejected as expected.")
}
