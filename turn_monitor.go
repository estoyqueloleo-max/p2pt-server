package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TurnSession struct {
	Username      string    `json:"username"`
	ClientIP      string    `json:"client_ip"`
	RelayAddr     string    `json:"relay_addr"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	BytesRelayed  int64     `json:"bytes_relayed"`
	PacketsCount  int64     `json:"packets_count"`
	LastActivity  time.Time `json:"last_activity"`
	IsTokenAuth   bool      `json:"is_token_auth"`
	Status        string    `json:"status"` // "active", "expired", "suspicious", "blocked"
}

type IPReputation struct {
	IP             string    `json:"ip"`
	Failures       int       `json:"failures"`
	LastFailure    time.Time `json:"last_failure"`
	BlockedUntil   time.Time `json:"blocked_until"`
	SuccessCount   int       `json:"success_count"`
}

type TurnMonitor struct {
	sessions    map[string]*TurnSession // key: username or relay_addr
	reputations map[string]*IPReputation
	mu          sync.RWMutex
}

func NewTurnMonitor() *TurnMonitor {
	tm := &TurnMonitor{
		sessions:    make(map[string]*TurnSession),
		reputations: make(map[string]*IPReputation),
	}
	tm.startCleanupRoutine()
	return tm
}

func (tm *TurnMonitor) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tm.cleanupExpired()
		}
	}()
}

func (tm *TurnMonitor) cleanupExpired() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	for key, s := range tm.sessions {
		if now.After(s.ExpiresAt) && now.Sub(s.LastActivity) > 2*time.Minute {
			delete(tm.sessions, key)
		}
	}
}

// CheckIPBlocked returns true if IP is currently banned due to auth abuse
func (tm *TurnMonitor) CheckIPBlocked(srcAddr net.Addr) bool {
	if srcAddr == nil {
		return false
	}
	ip := extractIP(srcAddr.String())

	tm.mu.RLock()
	rep, exists := tm.reputations[ip]
	tm.mu.RUnlock()

	if exists && time.Now().Before(rep.BlockedUntil) {
		return true
	}
	return false
}

// RecordAuthAttempt logs auth success/failure and detects brute-force / abuse
func (tm *TurnMonitor) RecordAuthAttempt(username string, srcAddr net.Addr, success bool) {
	if srcAddr == nil {
		return
	}
	ip := extractIP(srcAddr.String())
	now := time.Now()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	rep, exists := tm.reputations[ip]
	if !exists {
		rep = &IPReputation{IP: ip}
		tm.reputations[ip] = rep
	}

	if success {
		rep.SuccessCount++
		rep.Failures = 0 // reset failure counter on success

		// Parse token expiration if username format is <timestamp>:<peer>
		expiresAt := now.Add(24 * time.Hour)
		isToken := false

		parts := strings.Split(username, ":")
		if len(parts) >= 2 {
			if ts, err := strconv.ParseInt(parts[0], 10, 64); err == nil && ts > 0 {
				expiresAt = time.Unix(ts, 0)
				isToken = true
			}
		}

		sessionKey := fmt.Sprintf("%s@%s", username, ip)
		tm.sessions[sessionKey] = &TurnSession{
			Username:     username,
			ClientIP:     ip,
			CreatedAt:    now,
			ExpiresAt:    expiresAt,
			LastActivity: now,
			IsTokenAuth:  isToken,
			Status:       "active",
		}
	} else {
		rep.Failures++
		rep.LastFailure = now

		// If > 20 failed attempts in short window, temporarily block IP for 10 minutes
		if rep.Failures >= 20 {
			rep.BlockedUntil = now.Add(10 * time.Minute)
		}
	}
}

// RecordPacket updates traffic stats for a session
func (tm *TurnMonitor) RecordPacket(username string, clientIP string, bytes int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	sessionKey := fmt.Sprintf("%s@%s", username, clientIP)
	if s, exists := tm.sessions[sessionKey]; exists {
		s.BytesRelayed += int64(bytes)
		s.PacketsCount++
		s.LastActivity = time.Now()
	}
}

// GetActiveSessions returns list of current sessions and stats
func (tm *TurnMonitor) GetActiveSessions() ([]*TurnSession, int, int) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	list := make([]*TurnSession, 0, len(tm.sessions))
	now := time.Now()
	activeCount := 0
	blockedCount := 0

	for _, s := range tm.sessions {
		if now.After(s.ExpiresAt) {
			s.Status = "expired"
		} else {
			s.Status = "active"
			activeCount++
		}
		list = append(list, s)
	}

	for _, rep := range tm.reputations {
		if now.Before(rep.BlockedUntil) {
			blockedCount++
		}
	}

	return list, activeCount, blockedCount
}

// BlockIP manually bans an IP from connecting to TURN for a given duration (or 24h by default)
func (tm *TurnMonitor) BlockIP(ip string, duration time.Duration) {
	if ip == "" {
		return
	}
	if duration <= 0 {
		duration = 24 * time.Hour
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	rep, exists := tm.reputations[ip]
	if !exists {
		rep = &IPReputation{IP: ip}
		tm.reputations[ip] = rep
	}
	rep.BlockedUntil = time.Now().Add(duration)

	// Close / mark sessions from this IP as blocked
	for key, s := range tm.sessions {
		if s.ClientIP == ip {
			s.Status = "blocked"
			delete(tm.sessions, key)
		}
	}
}

// UnblockIP removes an IP from the blocklist
func (tm *TurnMonitor) UnblockIP(ip string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if rep, exists := tm.reputations[ip]; exists {
		rep.BlockedUntil = time.Time{}
		rep.Failures = 0
	}
}

// RevokeSession immediately removes an active session
func (tm *TurnMonitor) RevokeSession(sessionKey string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.sessions[sessionKey]; exists {
		delete(tm.sessions, sessionKey)
		return
	}
	for key, s := range tm.sessions {
		if s.Username == sessionKey || fmt.Sprintf("%s@%s", s.Username, s.ClientIP) == sessionKey {
			delete(tm.sessions, key)
			break
		}
	}
}

// GetBlockedIPs returns a list of all currently blocked IPs
func (tm *TurnMonitor) GetBlockedIPs() []*IPReputation {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var blocked []*IPReputation
	now := time.Now()
	for _, rep := range tm.reputations {
		if now.Before(rep.BlockedUntil) {
			blocked = append(blocked, rep)
		}
	}
	return blocked
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
