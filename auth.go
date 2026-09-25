package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookieName = "pingo_session"
	SessionDuration   = 24 * time.Hour
	MaxLoginFailures  = 5
	LockoutDuration   = 5 * time.Minute
)

// SessionInfo represents an active authenticated user session
type SessionInfo struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	ClientIP  string
}

// LoginAttempt tracks failed login attempts for rate-limiting
type LoginAttempt struct {
	Failures     int
	BlockedUntil time.Time
}

// AuthManager coordinates dashboard and API security
type AuthManager struct {
	adminPassword string
	allowWANDash  bool
	sessions      map[string]*SessionInfo
	attempts      map[string]*LoginAttempt
	mu            sync.RWMutex
}

// NewAuthManager initializes a new AuthManager with background cleanup
func NewAuthManager(adminPassword string, allowWANDash bool) *AuthManager {
	mgr := &AuthManager{
		adminPassword: strings.TrimSpace(adminPassword),
		allowWANDash:  allowWANDash,
		sessions:      make(map[string]*SessionInfo),
		attempts:      make(map[string]*LoginAttempt),
	}

	// Background routine to cleanup expired sessions and old lockout entries
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			mgr.cleanupExpired()
		}
	}()

	return mgr
}

// GetAdminPassword returns the current admin password
func (a *AuthManager) GetAdminPassword() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.adminPassword
}

// SetAdminPassword updates the admin password in runtime
func (a *AuthManager) SetAdminPassword(newPass string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.adminPassword = strings.TrimSpace(newPass)
	// Invalidate all existing sessions on password change
	a.sessions = make(map[string]*SessionInfo)
}

func (a *AuthManager) cleanupExpired() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for token, s := range a.sessions {
		if now.After(s.ExpiresAt) {
			delete(a.sessions, token)
		}
	}

	for ip, att := range a.attempts {
		if att.BlockedUntil.Before(now) && att.Failures == 0 {
			delete(a.attempts, ip)
		}
	}
}

// GetClientIP extracts the peer IP from RemoteAddr
func (a *AuthManager) GetClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.TrimSpace(host)
}

// IsPrivateOrLocalRequest determines if an incoming request originates from a local or private network
func (a *AuthManager) IsPrivateOrLocalRequest(r *http.Request) bool {
	clientIP := a.GetClientIP(r)
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return false
	}
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
		return true
	}

	// For IPv6, check if client IP belongs to any local interface subnet or shares the /64 prefix
	if client16 := parsedIP.To16(); client16 != nil && parsedIP.To4() == nil {
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok {
						if ipnet.Contains(parsedIP) {
							return true
						}
						local16 := ipnet.IP.To16()
						if local16 != nil && ipnet.IP.To4() == nil {
							// Compare the first 8 bytes (/64 prefix) for global unicast IPv6 in same LAN
							if len(local16) >= 8 && len(client16) >= 8 && bytes.Equal(local16[:8], client16[:8]) {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

// ValidatePassword performs constant-time password comparison to mitigate timing attacks
func (a *AuthManager) ValidatePassword(candidate string) bool {
	a.mu.RLock()
	expected := a.adminPassword
	a.mu.RUnlock()

	cand := strings.TrimSpace(candidate)
	if expected == "" {
		expected = "admin"
	}

	if subtle.ConstantTimeCompare([]byte(cand), []byte(expected)) == 1 {
		return true
	}
	// Fallback de compatibilidad por defecto: aceptar tanto "admin" como "alpine"
	if (expected == "alpine" && cand == "admin") || (expected == "admin" && cand == "alpine") {
		return true
	}
	return false
}

// CheckRateLimit verifies if an IP is currently locked out
func (a *AuthManager) CheckRateLimit(ip string) (bool, time.Duration) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	att, exists := a.attempts[ip]
	if !exists {
		return false, 0
	}

	now := time.Now()
	if att.BlockedUntil.After(now) {
		return true, att.BlockedUntil.Sub(now)
	}

	return false, 0
}

// RecordFailedAttempt registers a failure and blocks the IP if the threshold is reached
func (a *AuthManager) RecordFailedAttempt(ip string) (remaining int, blocked bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	att, exists := a.attempts[ip]
	if !exists {
		att = &LoginAttempt{}
		a.attempts[ip] = att
	}

	att.Failures++
	if att.Failures >= MaxLoginFailures {
		att.BlockedUntil = time.Now().Add(LockoutDuration)
		att.Failures = 0
		log.Printf("[Security] 🚫 IP %s bloqueada durante %v tras repetidos intentos fallidos de login.", ip, LockoutDuration)
		return 0, true
	}

	return MaxLoginFailures - att.Failures, false
}

// RecordSuccessfulAttempt resets failed attempts counter
func (a *AuthManager) RecordSuccessfulAttempt(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.attempts, ip)
}

// CreateSession generates a cryptographically secure random session token
func (a *AuthManager) CreateSession(clientIP string) (*SessionInfo, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	sess := &SessionInfo{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(SessionDuration),
		ClientIP:  clientIP,
	}

	a.mu.Lock()
	a.sessions[token] = sess
	a.mu.Unlock()

	return sess, nil
}

// IsAuthenticated checks if the request has a valid session cookie or Authorization header
func (a *AuthManager) IsAuthenticated(r *http.Request) bool {
	// 1. Check Bearer token or direct admin password in Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Bearer <token_or_pass>
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if a.ValidatePassword(token) {
				return true
			}
			a.mu.RLock()
			sess, exists := a.sessions[token]
			valid := exists && time.Now().Before(sess.ExpiresAt)
			a.mu.RUnlock()
			if valid {
				return true
			}
		}

		// Basic Auth support: user:pass
		if u, p, ok := r.BasicAuth(); ok {
			_ = u
			if a.ValidatePassword(p) {
				return true
			}
		}
	}

	// 2. Check session cookie
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	a.mu.RLock()
	sess, exists := a.sessions[cookie.Value]
	valid := exists && time.Now().Before(sess.ExpiresAt)
	a.mu.RUnlock()

	return valid
}

// RequireAuth middleware protects routes requiring administration access
func (a *AuthManager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.applySecurityHeaders(w)

		if a.IsAuthenticated(r) {
			next(w, r)
			return
		}

		// If API or JSON request, return 401 Unauthorized
		if strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("Accept") == "application/json" {
			log.Printf("[Security] ❌ Acceso denegado a %s desde %s (No autenticado / Cookie o Token ausente)", r.URL.Path, a.GetClientIP(r))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Unauthorized",
				"message": "Se requiere autenticación de administrador para acceder a este recurso.",
			})
			return
		}

		// If browser requesting dashboard, render login screen
		if r.URL.Path == "/" || r.URL.Path == "" {
			// Check if WAN access is disabled and request is from WAN
			if !a.allowWANDash && !a.IsPrivateOrLocalRequest(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status":  "ok",
					"service": "pingo-signaling",
				})
				return
			}

			a.RenderLoginPage(w, r, "")
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// RequireLocalNetwork middleware restricts hardware-modifying endpoints to LAN/Hotspot
func (a *AuthManager) RequireLocalNetwork(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.IsPrivateOrLocalRequest(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			log.Printf("[Security] ⚠️ Intento de acceso a endpoint de hardware (%s) bloqueado desde IP pública: %s", r.URL.Path, a.GetClientIP(r))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Forbidden",
				"message": "Operación restringida: Por seguridad del appliance, la configuración de hardware/red solo puede realizarse desde la red local (LAN) o el modo Hotspot.",
			})
			return
		}
		next(w, r)
	}
}

func (a *AuthManager) applySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
}

// HandleLogin processes authentication requests
func (a *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	a.applySecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	clientIP := a.GetClientIP(r)

	// Check rate-limiting lockout
	if blocked, duration := a.CheckRateLimit(clientIP); blocked {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Demasiados intentos fallidos.",
			"blocked":   true,
			"wait_secs": int(duration.Seconds()),
			"message":   fmt.Sprintf("Acceso bloqueado temporalmente. Espera %d segundos antes de reintentar.", int(duration.Seconds())),
		})
		return
	}

	var payload struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if !a.ValidatePassword(payload.Password) {
		remaining, locked := a.RecordFailedAttempt(clientIP)
		w.WriteHeader(http.StatusUnauthorized)
		if locked {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Contraseña incorrecta.",
				"locked":  true,
				"message": fmt.Sprintf("Has excedido el número máximo de intentos. IP bloqueada durante %v.", LockoutDuration),
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":              "Contraseña incorrecta.",
				"remaining_attempts": remaining,
				"message":            fmt.Sprintf("Contraseña incorrecta. Te quedan %d intentos antes del bloqueo.", remaining),
			})
		}
		return
	}

	// Login successful
	a.RecordSuccessfulAttempt(clientIP)
	sess, err := a.CreateSession(clientIP)
	if err != nil {
		http.Error(w, `{"error":"Failed to create session"}`, http.StatusInternalServerError)
		return
	}

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("[Security] ✅ Inicio de sesión de administrador exitoso desde %s", clientIP)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"token":   sess.Token,
		"message": "Autenticación correcta",
	})
}

// HandleLogout terminates the active session
func (a *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	a.applySecurityHeaders(w)

	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	if r.Header.Get("Accept") == "application/json" || strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Sesión cerrada correctamente",
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleAuthCheck provides session status information
func (a *AuthManager) HandleAuthCheck(w http.ResponseWriter, r *http.Request) {
	a.applySecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated":     a.IsAuthenticated(r),
		"is_local":          a.IsPrivateOrLocalRequest(r),
		"allow_wan_dash":    a.allowWANDash,
		"client_ip":         a.GetClientIP(r),
	})
}

// RenderLoginPage displays a sleek glassmorphic login interface with Wi-Fi provisioning in local/hotspot mode
func (a *AuthManager) RenderLoginPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	a.applySecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	isLocal := a.IsPrivateOrLocalRequest(r)
	clientIP := a.GetClientIP(r)
	isHotspot := strings.HasPrefix(clientIP, "192.168.4.") || clientIP == "127.0.0.1" || clientIP == "::1"

	networkBadge := `<span style="display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:9999px; font-size:0.75rem; background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3);">🟢 Red Local (` + clientIP + `)</span>`
	if !isLocal {
		networkBadge = `<span style="display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:9999px; font-size:0.75rem; background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.3);">🌐 Conexión Externa WAN (` + clientIP + `)</span>`
	}

	data := struct {
		ErrorMsg     string
		NetworkBadge template.HTML
		IsLocal      bool
		IsHotspot    bool
		ClientIP     string
	}{
		ErrorMsg:     errorMsg,
		NetworkBadge: template.HTML(networkBadge),
		IsLocal:      isLocal,
		IsHotspot:    isHotspot,
		ClientIP:     clientIP,
	}

	tmpl := template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pingo Appliance — Configuración & Acceso</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.90);
            --border-color: rgba(255, 255, 255, 0.10);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #10b981;
            --accent-hover: #059669;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: radial-gradient(circle at top right, #1e1b4b 0%, var(--bg-color) 60%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
        }
        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.1);
            backdrop-filter: blur(16px);
            width: 100%;
            max-width: 480px;
            padding: 28px;
            text-align: center;
            animation: fadeIn 0.3s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .logo-icon {
            width: 52px;
            height: 52px;
            margin: 0 auto 12px;
            border-radius: 14px;
            background: linear-gradient(135deg, rgba(16,185,129,0.2) 0%, rgba(59,130,246,0.2) 100%);
            border: 1px solid rgba(16,185,129,0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
        }
        h1 {
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 4px;
        }
        .subtitle {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 16px;
        }
        .badge-wrapper {
            margin-bottom: 18px;
        }
        .tabs-nav {
            display: flex;
            gap: 6px;
            margin-bottom: 20px;
            background: rgba(0,0,0,0.35);
            padding: 4px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }
        .tab-btn {
            flex: 1;
            padding: 9px 12px;
            border: none;
            border-radius: 7px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            background: transparent;
            color: var(--text-muted);
            transition: all 0.2s;
        }
        .tab-btn.active {
            background: var(--accent);
            color: #fff;
            box-shadow: 0 2px 8px rgba(16,185,129,0.3);
        }
        .form-group {
            text-align: left;
            margin-bottom: 16px;
        }
        label {
            display: block;
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .input-wrap {
            position: relative;
        }
        input[type="password"], input[type="text"], select {
            width: 100%;
            background: rgba(0,0,0,0.35);
            border: 1px solid rgba(255,255,255,0.15);
            color: #fff;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 0.92rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        select option {
            background: #111827;
            color: #fff;
        }
        input:focus, select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(16,185,129,0.25);
        }
        .toggle-btn {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 1.1rem;
            padding: 4px;
        }
        .toggle-btn:hover { color: #fff; }
        .btn-submit {
            width: 100%;
            background: var(--accent);
            color: #fff;
            font-weight: 600;
            font-size: 0.95rem;
            padding: 12px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
        }
        .btn-submit:hover {
            background: var(--accent-hover);
        }
        .btn-submit:active {
            transform: scale(0.98);
        }
        .btn-submit:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .alert-box {
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 0.85rem;
            margin-bottom: 16px;
            text-align: left;
            display: none;
        }
        .alert-error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }
        .alert-success {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
        }
        .footer-note {
            margin-top: 20px;
            font-size: 0.75rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo-icon">🛡️</div>
        <h1>Pingo Appliance</h1>
        <div class="subtitle">Portal de Aprovisionamiento y Control</div>
        
        <div class="badge-wrapper">
            {{.NetworkBadge}}
        </div>

        {{if .IsLocal}}
        <div class="tabs-nav">
            <button type="button" id="tab-btn-wifi" class="tab-btn {{if .IsHotspot}}active{{end}}" onclick="switchPortalTab('wifi')">📶 Conectar a Wi-Fi</button>
            <button type="button" id="tab-btn-admin" class="tab-btn {{if not .IsHotspot}}active{{end}}" onclick="switchPortalTab('admin')">🔑 Administrador</button>
        </div>
        {{end}}

        <div id="alert-box" class="alert-box alert-error"></div>

        {{if .IsLocal}}
        <!-- PESTAÑA APROVISIONAMIENTO WI-FI -->
        <div id="tab-wifi-panel" {{if not .IsHotspot}}style="display:none;"{{end}}>
            <p style="font-size: 0.84rem; color: var(--text-muted); text-align: left; margin-bottom: 14px; line-height: 1.4;">
                Selecciona la red Wi-Fi de tu hogar (2.4 GHz) para que la Raspberry Pi se conecte a Internet y salga del modo Hotspot:
            </p>

            <form id="portal-wifi-form" action="javascript:void(0)" onsubmit="handlePortalWiFiSave(event); return false;">
                <div class="form-group">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <label style="margin:0;">Red Wi-Fi Detectada</label>
                        <button type="button" id="portal-scan-btn" onclick="scanPortalWiFiNetworks()" style="background: rgba(255,255,255,0.08); border: 1px solid var(--border-color); color: var(--text-main); font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; cursor: pointer;">
                            🔄 Actualizar Redes
                        </button>
                    </div>
                    <select id="portal-wifi-select" onchange="handlePortalWiFiSelect(this.value)">
                        <option value="">⏳ Escaneando redes cercanas...</option>
                    </select>
                    <input type="text" id="portal-wifi-ssid" placeholder="Nombre de red (SSID manual u oculto)" style="display:none; margin-top:8px;">
                </div>

                <div class="form-group">
                    <label>Contraseña de tu red Wi-Fi</label>
                    <input type="password" id="portal-wifi-pass" placeholder="Clave de tu router Wi-Fi">
                </div>

                <div style="margin-top: 10px; margin-bottom: 12px; display: flex; align-items: center; gap: 16px; justify-content: flex-start;">
                    <label style="font-size: 0.82rem; color: var(--text-main); display: flex; align-items: center; gap: 6px; cursor: pointer; margin:0;" onclick="setPortalIPMode('dhcp')">
                        <input type="radio" id="portal-ip-dhcp" name="portal_ip_mode" value="dhcp" checked onclick="setPortalIPMode('dhcp')"> 🟢 DHCP (Auto)
                    </label>
                    <label style="font-size: 0.82rem; color: var(--text-main); display: flex; align-items: center; gap: 6px; cursor: pointer; margin:0;" onclick="setPortalIPMode('static')">
                        <input type="radio" id="portal-ip-static" name="portal_ip_mode" value="static" onclick="setPortalIPMode('static')"> ⚙️ IP Estática
                    </label>
                </div>

                <div id="portal-static-container" style="display: none; margin-bottom: 14px; background: rgba(0,0,0,0.25); padding: 10px; border-radius: 8px; border: 1px solid var(--border-color); text-align: left;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                        <div>
                            <label style="font-size:0.75rem;">IP Deseada</label>
                            <input type="text" id="portal-ip-val" value="192.168.1.50" style="padding:6px 10px; font-size:0.85rem;">
                        </div>
                        <div>
                            <label style="font-size:0.75rem;">Router (Gateway)</label>
                            <input type="text" id="portal-gw-val" value="192.168.1.1" style="padding:6px 10px; font-size:0.85rem;">
                        </div>
                        <div>
                            <label style="font-size:0.75rem;">Máscara</label>
                            <input type="text" id="portal-mask-val" value="255.255.255.0" style="padding:6px 10px; font-size:0.85rem;">
                        </div>
                        <div>
                            <label style="font-size:0.75rem;">DNS</label>
                            <input type="text" id="portal-dns-val" value="1.1.1.1 8.8.8.8" style="padding:6px 10px; font-size:0.85rem;">
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Contraseña de Administrador del Appliance</label>
                    <input type="password" id="portal-admin-pass" placeholder="Clave del appliance (defecto: admin)" value="admin">
                </div>

                <button type="submit" id="portal-wifi-submit" class="btn-submit">🚀 Guardar y Conectar Appliance</button>
            </form>
        </div>
        {{end}}

        <!-- PESTAÑA LOGIN ADMIN -->
        <div id="tab-admin-panel" {{if and .IsLocal .IsHotspot}}style="display:none;"{{end}}>
            <form id="login-form" action="javascript:void(0)" onsubmit="handleLogin(event); return false;">
                <div class="form-group">
                    <label for="password">Contraseña de Administrador</label>
                    <div class="input-wrap">
                        <input type="password" id="password" name="password" placeholder="Introduce tu clave de acceso" required autofocus autocomplete="current-password">
                        <button type="button" class="toggle-btn" onclick="togglePassVisibility()" title="Mostrar/ocultar contraseña">👁️</button>
                    </div>
                </div>
                <button type="submit" id="submit-btn" class="btn-submit">Entrar al Dashboard</button>
            </form>
        </div>

        <div class="footer-note">
            🔒 El servicio P2P y TURN continúa funcionando en segundo plano sin interrupción.
        </div>
    </div>

    <script>
        function togglePassVisibility() {
            const passInput = document.getElementById("password");
            if (passInput) {
                passInput.type = passInput.type === "password" ? "text" : "password";
            }
        }

        function switchPortalTab(tab) {
            const wifiPanel = document.getElementById("tab-wifi-panel");
            const adminPanel = document.getElementById("tab-admin-panel");
            const wifiBtn = document.getElementById("tab-btn-wifi");
            const adminBtn = document.getElementById("tab-btn-admin");
            const alertBox = document.getElementById("alert-box");
            if (alertBox) alertBox.style.display = "none";

            if (tab === 'wifi') {
                if (wifiPanel) wifiPanel.style.display = "block";
                if (adminPanel) adminPanel.style.display = "none";
                if (wifiBtn) wifiBtn.classList.add("active");
                if (adminBtn) adminBtn.classList.remove("active");
            } else {
                if (wifiPanel) wifiPanel.style.display = "none";
                if (adminPanel) adminPanel.style.display = "block";
                if (wifiBtn) wifiBtn.classList.remove("active");
                if (adminBtn) adminBtn.classList.add("active");
                const passField = document.getElementById("password");
                if (passField) passField.focus();
            }
        }

        function setPortalIPMode(mode) {
            const container = document.getElementById("portal-static-container");
            const dhcpRadio = document.getElementById("portal-ip-dhcp");
            const staticRadio = document.getElementById("portal-ip-static");
            if (mode === 'static') {
                if (staticRadio) staticRadio.checked = true;
                if (dhcpRadio) dhcpRadio.checked = false;
                if (container) container.style.display = 'block';
            } else {
                if (dhcpRadio) dhcpRadio.checked = true;
                if (staticRadio) staticRadio.checked = false;
                if (container) container.style.display = 'none';
            }
        }

        function handlePortalWiFiSelect(val) {
            const manualInput = document.getElementById("portal-wifi-ssid");
            const passInput = document.getElementById("portal-wifi-pass");
            if (val === '__MANUAL__') {
                manualInput.style.display = 'block';
                manualInput.focus();
            } else if (val) {
                manualInput.style.display = 'none';
                manualInput.value = val;
                if (passInput) passInput.focus();
            }
        }

        async function scanPortalWiFiNetworks() {
            const btn = document.getElementById('portal-scan-btn');
            const select = document.getElementById('portal-wifi-select');
            const manualInput = document.getElementById('portal-wifi-ssid');
            if (btn) {
                btn.disabled = true;
                btn.innerText = "⏳ Buscando...";
            }
            if (select) {
                select.innerHTML = '<option value="">⏳ Escaneando redes cercanas...</option>';
            }

            try {
                const token = localStorage.getItem('pingo_session_token') || '';
                const headers = {};
                if (token) headers['Authorization'] = 'Bearer ' + token;

                const res = await fetch('/api/wifi/scan', {
                    credentials: 'include',
                    headers: headers
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const msg = errData.message || ('Error ' + res.status);
                    select.innerHTML = '<option value="__MANUAL__">⚠️ No se pudo escanear (' + msg + ') - Escribir SSID manual</option>';
                    if (manualInput) manualInput.style.display = 'block';
                    return;
                }

                const data = await res.json();
                if (data.networks && data.networks.length > 0) {
                    select.innerHTML = '<option value="">-- Selecciona tu red Wi-Fi (' + data.networks.length + ' detectadas) --</option>';
                    data.networks.forEach(n => {
                        const opt = document.createElement('option');
                        opt.value = n.ssid;
                        opt.innerText = '📶 ' + n.ssid + (n.signal && n.signal > -100 ? ' (' + n.signal + ' dBm)' : '');
                        select.appendChild(opt);
                    });
                    const manualOpt = document.createElement('option');
                    manualOpt.value = '__MANUAL__';
                    manualOpt.innerText = '✏️ Escribir otra red (SSID manual u oculta)...';
                    select.appendChild(manualOpt);
                } else {
                    select.innerHTML = '<option value="__MANUAL__">🔍 0 redes detectadas (Pulsa Actualizar o escribe el SSID)</option>';
                    if (manualInput) manualInput.style.display = 'block';
                }
            } catch (e) {
                select.innerHTML = '<option value="__MANUAL__">⚠️ Error de conexión al escanear - Escribir SSID manual</option>';
                if (manualInput) manualInput.style.display = 'block';
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = "🔄 Actualizar Redes";
                }
            }
        }

        async function handlePortalWiFiSave(e) {
            e.preventDefault();
            const btn = document.getElementById("portal-wifi-submit");
            const alertBox = document.getElementById("alert-box");
            const select = document.getElementById("portal-wifi-select");
            const manualInput = document.getElementById("portal-wifi-ssid");
            const passInput = document.getElementById("portal-wifi-pass");
            const adminPassInput = document.getElementById("portal-admin-pass");
            const staticRadio = document.getElementById("portal-ip-static");

            let ssid = (select && select.value && select.value !== '__MANUAL__') ? select.value : (manualInput ? manualInput.value.trim() : '');
            if (!ssid && manualInput) ssid = manualInput.value.trim();

            if (!ssid) {
                alertBox.className = "alert-box alert-error";
                alertBox.innerText = "Debes seleccionar o escribir el nombre de tu red Wi-Fi (SSID).";
                alertBox.style.display = "block";
                return;
            }

            const password = passInput ? passInput.value : '';
            const adminPassword = adminPassInput ? adminPassInput.value : 'admin';
            const ipMode = (staticRadio && staticRadio.checked) ? "static" : "dhcp";

            btn.disabled = true;
            btn.innerText = "⏳ Guardando configuración...";
            alertBox.style.display = "none";

            const payload = {
                ssid: ssid,
                password: password,
                ip_mode: ipMode,
                ip: document.getElementById("portal-ip-val") ? document.getElementById("portal-ip-val").value.trim() : "192.168.1.50",
                netmask: document.getElementById("portal-mask-val") ? document.getElementById("portal-mask-val").value.trim() : "255.255.255.0",
                gateway: document.getElementById("portal-gw-val") ? document.getElementById("portal-gw-val").value.trim() : "192.168.1.1",
                dns: document.getElementById("portal-dns-val") ? document.getElementById("portal-dns-val").value.trim() : "1.1.1.1 8.8.8.8",
                reboot: true,
                admin_password: adminPassword
            };

            try {
                const token = localStorage.getItem('pingo_session_token') || '';
                const headers = { "Content-Type": "application/json" };
                if (token) headers['Authorization'] = 'Bearer ' + token;

                const resp = await fetch("/api/wifi/configure", {
                    method: "POST",
                    credentials: 'include',
                    headers: headers,
                    body: JSON.stringify(payload)
                });

                const data = await resp.json().catch(() => ({}));
                if (resp.ok && data.success) {
                    alertBox.className = "alert-box alert-success";
                    alertBox.innerHTML = "✅ <b>¡Configuración Wi-Fi guardada con éxito!</b><br>El appliance se está reiniciando para conectarse a '" + ssid + "'. En 30-40 segundos podrás acceder a través de tu red local.";
                    alertBox.style.display = "block";
                    btn.innerText = "🔄 Reiniciando dispositivo...";
                } else {
                    alertBox.className = "alert-box alert-error";
                    alertBox.innerText = data.message || data.error || "Error al guardar la configuración Wi-Fi.";
                    alertBox.style.display = "block";
                    btn.disabled = false;
                    btn.innerText = "🚀 Guardar y Conectar Appliance";
                }
            } catch (err) {
                alertBox.className = "alert-box alert-error";
                alertBox.innerText = "Error de comunicación con el appliance al guardar.";
                alertBox.style.display = "block";
                btn.disabled = false;
                btn.innerText = "🚀 Guardar y Conectar Appliance";
            }
        }

        async function handleLogin(e) {
            e.preventDefault();
            const btn = document.getElementById("submit-btn");
            const alertBox = document.getElementById("alert-box");
            const password = document.getElementById("password").value;

            btn.disabled = true;
            btn.innerText = "Verificando...";
            alertBox.style.display = "none";

            try {
                const resp = await fetch("/api/auth/login", {
                    method: "POST",
                    credentials: 'include',
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password: password })
                });

                const data = await resp.json();

                if (resp.ok && data.success) {
                    btn.innerText = "¡Acceso concedido!";
                    btn.style.background = "#059669";
                    if (data.token) {
                        localStorage.setItem('pingo_session_token', data.token);
                    }
                    setTimeout(() => {
                        window.location.href = window.location.protocol + "//" + window.location.host + "/";
                    }, 300);
                } else {
                    alertBox.className = "alert-box alert-error";
                    alertBox.innerText = data.message || data.error || "Error de autenticación.";
                    alertBox.style.display = "block";
                    btn.disabled = false;
                    btn.innerText = "Entrar al Dashboard";
                    document.getElementById("password").focus();
                    document.getElementById("password").select();
                }
            } catch (err) {
                alertBox.className = "alert-box alert-error";
                alertBox.innerText = "Error de conexión con el servidor.";
                alertBox.style.display = "block";
                btn.disabled = false;
                btn.innerText = "Entrar al Dashboard";
            }
        }

        window.addEventListener('DOMContentLoaded', () => {
            const wifiPanel = document.getElementById("tab-wifi-panel");
            if (wifiPanel && wifiPanel.style.display !== "none") {
                scanPortalWiFiNetworks();
            }
        });
    </script>
</body>
</html>`))

	_ = tmpl.Execute(w, data)
}

