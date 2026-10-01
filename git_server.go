//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sosedoff/gitkit"
)

// GitServer manages Smart HTTP Git access and private repository isolation
type GitServer struct {
	cfg          *Config
	authMgr      *AuthManager
	gitkitServer *gitkit.Server
	rootDir      string
	claimsFile   string
	claims       map[string]*PeerClaim
	revokedPeers map[string]time.Time
	mu           sync.RWMutex
}

// RepoInfo represents metadata of a hosted git repository
type RepoInfo struct {
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size_bytes"`
	LastCommit time.Time `json:"last_commit,omitempty"`
	URL        string    `json:"url"`
}

// NewGitServer initializes and configures the embedded Git server
func NewGitServer(cfg *Config, authMgr *AuthManager) (*GitServer, error) {
	rootDir := cfg.GitDir
	if rootDir == "" {
		// Prefer persistent /var/lib/p2pt/repos if writable, otherwise ./data/repos
		if err := os.MkdirAll("/var/lib/p2pt/repos", 0755); err == nil {
			rootDir = "/var/lib/p2pt/repos"
		} else {
			rootDir = "./data/repos"
		}
	}

	absRootDir, err := filepath.Abs(rootDir)
	if err != nil {
		absRootDir = rootDir
	}

	if err := os.MkdirAll(absRootDir, 0755); err != nil {
		return nil, fmt.Errorf("fallo al crear directorio base de git %s: %w", absRootDir, err)
	}

	claimsPath := filepath.Join(absRootDir, ".git_claims.json")
	gs := &GitServer{
		cfg:          cfg,
		authMgr:      authMgr,
		rootDir:      absRootDir,
		claimsFile:   claimsPath,
		claims:       make(map[string]*PeerClaim),
		revokedPeers: make(map[string]time.Time),
	}
	gs.loadClaims()

	// Configure gitkit
	gkConfig := gitkit.Config{
		Dir:        absRootDir,
		AutoCreate: true,
		AutoHooks:  false,
		Auth:       true,
	}

	// Detect git binary path
	if gitPath, err := exec.LookPath("git"); err == nil {
		gkConfig.GitPath = gitPath
	}

	gk := gitkit.New(gkConfig)
	gk.AuthFunc = gs.authenticateRequest

	if err := gk.Setup(); err != nil {
		return nil, fmt.Errorf("error inicializando motor gitkit: %w", err)
	}

	gs.gitkitServer = gk
	log.Printf("[GitServer] 📦 Servidor Git Smart HTTP activo. Directorio base: %s", absRootDir)
	return gs, nil
}

func (gs *GitServer) loadClaims() {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	data, err := os.ReadFile(gs.claimsFile)
	if err != nil {
		return
	}
	var loaded map[string]*PeerClaim
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		gs.claims = loaded
		for peer, claim := range loaded {
			if claim.Revoked {
				gs.revokedPeers[peer] = time.Now()
			}
		}
	}
}

func (gs *GitServer) saveClaimsLocked() {
	if gs.claimsFile == "" {
		return
	}
	data, err := json.MarshalIndent(gs.claims, "", "  ")
	if err == nil {
		_ = os.WriteFile(gs.claimsFile, data, 0644)
	}
}

// RevokePeer revokes Git access for a specific peerId
func (gs *GitServer) RevokePeer(peerID string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	clean := strings.TrimSpace(peerID)
	gs.revokedPeers[clean] = time.Now()
	if c, ok := gs.claims[clean]; ok {
		c.Revoked = true
	}
	gs.saveClaimsLocked()
}

// UnrevokePeer restores Git access for a previously revoked peerId
func (gs *GitServer) UnrevokePeer(peerID string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	clean := strings.TrimSpace(peerID)
	delete(gs.revokedPeers, clean)
	if c, ok := gs.claims[clean]; ok {
		c.Revoked = false
	}
	gs.saveClaimsLocked()
}

// UnlockPeerClaim clears a claim lock so another device can claim the peerId
func (gs *GitServer) UnlockPeerClaim(peerID string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	clean := strings.TrimSpace(peerID)
	delete(gs.claims, clean)
	gs.saveClaimsLocked()
}

// IsPeerRevoked checks whether a peerId has been revoked by admin
func (gs *GitServer) IsPeerRevoked(peerID string) bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	clean := strings.TrimSpace(peerID)
	if c, ok := gs.claims[clean]; ok && c.Revoked {
		return true
	}
	_, exists := gs.revokedPeers[clean]
	return exists
}

// GetRevokedPeers returns a slice of currently revoked peerIds
func (gs *GitServer) GetRevokedPeers() []string {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	revokedMap := make(map[string]bool)
	for p := range gs.revokedPeers {
		revokedMap[p] = true
	}
	for p, c := range gs.claims {
		if c.Revoked {
			revokedMap[p] = true
		}
	}
	list := make([]string, 0, len(revokedMap))
	for p := range revokedMap {
		list = append(list, p)
	}
	return list
}

// GetPeerClaim returns a copy of the claim for peerID, or nil
func (gs *GitServer) GetPeerClaim(peerID string) *PeerClaim {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	c, ok := gs.claims[strings.TrimSpace(peerID)]
	if !ok {
		return nil
	}
	cp := *c
	return &cp
}

// GetAllClaims returns a copy of all active peer claims
func (gs *GitServer) GetAllClaims() map[string]*PeerClaim {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	res := make(map[string]*PeerClaim, len(gs.claims))
	for k, v := range gs.claims {
		cp := *v
		res[k] = &cp
	}
	return res
}

// authenticateRequest validates credentials and enforces per-user repository isolation
func (gs *GitServer) authenticateRequest(cred gitkit.Credential, req *gitkit.Request) (bool, error) {
	username := strings.TrimSpace(cred.Username)
	password := strings.TrimSpace(cred.Password)

	if username == "" || password == "" {
		return false, fmt.Errorf("credenciales vacías")
	}

	// Determine namespace (first segment of RepoName, e.g. "peerId/routes.git" -> "peerId")
	parts := strings.Split(strings.Trim(req.RepoName, "/"), "/")
	repoNamespace := ""
	if len(parts) > 1 {
		repoNamespace = parts[0]
	}

	// 1. Check if peer is explicitly revoked
	if gs.IsPeerRevoked(username) {
		log.Printf("[GitServer] 🚫 Peer '%s' revocado por el administrador, denegando acceso", username)
		return false, fmt.Errorf("acceso denegado: peer revocado")
	}

	// 2. Validate ephemeral Git Token (HMAC-SHA256)
	secret := gs.cfg.AuthSecret
	if secret == "" {
		secret = gs.cfg.Password
	}
	isValidGitToken := ValidateGitToken(secret, username, password)

	// If token has valid HMAC, enforce device claim match
	if isValidGitToken {
		gs.mu.Lock()
		claim, hasClaim := gs.claims[username]
		if hasClaim {
			if claim.Revoked {
				gs.mu.Unlock()
				return false, fmt.Errorf("acceso denegado: peer revocado")
			}
			if HashGitToken(password) != claim.TokenHash {
				gs.mu.Unlock()
				log.Printf("[GitServer] 🚫 Token no coincide con el dispositivo reclamado para peer '%s'", username)
				return false, fmt.Errorf("token desactualizado o no válido para este dispositivo")
			}
			claim.LastUsed = time.Now()
			gs.saveClaimsLocked()
		}
		gs.mu.Unlock()
	}

	// 3. Appliance user credentials (from config, for backwards compatibility)
	isApplianceUser := (username == gs.cfg.Username && password == gs.cfg.Password)

	// 4. Admin password
	isAdmin := gs.authMgr != nil && gs.authMgr.ValidatePassword(password)

	// 5. Session token check (if bearer or token used as password)
	hasValidSession := false
	if gs.authMgr != nil {
		gs.authMgr.mu.RLock()
		sess, exists := gs.authMgr.sessions[password]
		if exists && time.Now().Before(sess.ExpiresAt) {
			hasValidSession = true
		}
		gs.authMgr.mu.RUnlock()
	}

	authenticated := isValidGitToken || isApplianceUser || isAdmin || hasValidSession
	if !authenticated {
		return false, fmt.Errorf("credenciales inválidas para git")
	}

	// Isolation Check: If repository belongs to a namespace, regular peers/users can only access their own.
	// Admins can access all repositories.
	if repoNamespace != "" && !isAdmin {
		if username != repoNamespace {
			log.Printf("[GitServer] 🚫 Acceso denegado: Peer/Usuario '%s' intentó acceder al repositorio privado de '%s'", username, repoNamespace)
			return false, fmt.Errorf("acceso no autorizado a este repositorio")
		}
	}

	// Post-create hook: if repo directory was newly initialized, ensure receivepack is enabled
	go gs.ensureRepoConfig(req.RepoPath)

	return true, nil
}

// ensureRepoConfig ensures the bare repository has receivepack enabled for pushes
func (gs *GitServer) ensureRepoConfig(repoPath string) {
	if _, err := os.Stat(filepath.Join(repoPath, "config")); err == nil {
		_ = exec.Command("git", "--git-dir="+repoPath, "config", "http.receivepack", "true").Run()
	}
}

// ServeHTTP handles Smart HTTP Git requests with complete CORS headers for isomorphic-git
func (gs *GitServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	// Universal CORS headers required by isomorphic-git / LightningFS in browsers
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Requested-With, X-Git-Protocol, User-Agent, Cache-Control")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type, X-Git-Protocol, WWW-Authenticate")

	// Preflight OPTIONS handler
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Strip "/git/" or "/git" prefix before passing to gitkit
	subPath := strings.TrimPrefix(r.URL.Path, "/git")
	if subPath == "" || subPath == "/" {
		http.Error(w, "Repositorio no especificado", http.StatusBadRequest)
		return
	}

	// Clone request with rewritten URL path
	r2 := r.Clone(r.Context())
	r2.URL.Path = subPath

	// Delegate to gitkit Smart HTTP server
	gs.gitkitServer.ServeHTTP(w, r2)
}

// HandleListRepos returns JSON listing of repositories for the authenticated user
func (gs *GitServer) HandleListRepos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if gs.authMgr != nil && !gs.authMgr.IsAuthenticated(r) {
		http.Error(w, `{"error":"No autorizado"}`, http.StatusUnauthorized)
		return
	}

	repos := gs.scanRepos()
	revoked := gs.GetRevokedPeers()
	claims := gs.GetAllClaims()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"root_dir":      gs.rootDir,
		"repos":         repos,
		"count":         len(repos),
		"revoked_peers": revoked,
		"claims":        claims,
	})
}

// HandleGitCredentials generates a per-peer private repository URL and ephemeral HMAC access token with First-Claim locking
func (gs *GitServer) HandleGitCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	peerID := strings.TrimSpace(r.URL.Query().Get("peerId"))
	if peerID == "" {
		peerID = strings.TrimSpace(r.URL.Query().Get("user"))
	}

	// Also support JSON body if POST
	if peerID == "" && r.Method == http.MethodPost {
		var req struct {
			PeerID string `json:"peerId"`
			User   string `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.PeerID != "" {
				peerID = strings.TrimSpace(req.PeerID)
			} else if req.User != "" {
				peerID = strings.TrimSpace(req.User)
			}
		}
	}

	if peerID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "peerId es requerido",
		})
		return
	}

	if gs.IsPeerRevoked(peerID) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "peer revocado por el administrador",
		})
		return
	}

	// Check First-Claim (TOFU) lock: If peer already claimed by another device, disallow anonymous re-issuance
	claim := gs.GetPeerClaim(peerID)
	if claim != nil && claim.TokenHash != "" {
		isAdmin := gs.authMgr != nil && gs.authMgr.IsAuthenticated(r)

		providedToken := strings.TrimSpace(r.URL.Query().Get("token"))
		if providedToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				providedToken = strings.TrimSpace(authHeader[7:])
			}
		}
		isOwner := providedToken != "" && HashGitToken(providedToken) == claim.TokenHash

		if !isAdmin && !isOwner {
			w.WriteHeader(http.StatusConflict) // 409 Conflict
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "peer_already_claimed",
				"message": fmt.Sprintf("El Peer '%s' ya ha sido reclamado y vinculado a otro dispositivo. Para vincular un nuevo dispositivo, el administrador debe desbloquearlo desde el Dashboard.", peerID),
				"claimed": true,
			})
			return
		}
	}

	// TTL: default 30 days (2592000 seconds)
	ttlSec := 30 * 24 * 3600
	if ttlStr := r.URL.Query().Get("ttl"); ttlStr != "" {
		if t, err := strconv.Atoi(ttlStr); err == nil && t > 0 {
			ttlSec = t
		}
	}
	expiry := time.Now().Add(time.Duration(ttlSec) * time.Second)

	secret := gs.cfg.AuthSecret
	if secret == "" {
		secret = gs.cfg.Password
	}
	token := GenerateGitToken(secret, peerID, expiry)

	// Register or update active device claim
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if gs.authMgr != nil {
		clientIP = gs.authMgr.GetClientIP(r)
	}

	gs.mu.Lock()
	gs.claims[peerID] = &PeerClaim{
		PeerID:    peerID,
		TokenHash: HashGitToken(token),
		ClaimedAt: time.Now(),
		ExpiresAt: expiry,
		ClientIP:  clientIP,
		LastUsed:  time.Now(),
		Revoked:   false,
	}
	gs.saveClaimsLocked()
	gs.mu.Unlock()

	proto := "http"
	if gs.cfg.EnableTLS {
		proto = "https"
	}
	repoName := gs.cfg.GitRepo
	if repoName == "" {
		repoName = "routes"
	}
	if !strings.HasSuffix(repoName, ".git") {
		repoName += ".git"
	}

	repoURL := fmt.Sprintf("%s://%s:%d/git/%s/%s", proto, gs.cfg.GetPublicIP(), gs.cfg.HTTPPort, peerID, repoName)

	resp := map[string]interface{}{
		"enabled":    true,
		"url":        repoURL,
		"username":   peerID,
		"token":      token,
		"repo":       repoName,
		"expires_at": expiry.Unix(),
		"ttl":        ttlSec,
		"claimed":    true,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// HandleUnlockPeer releases a peerId claim so it can be claimed by a new device
func (gs *GitServer) HandleUnlockPeer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PeerID) == "" {
		http.Error(w, `{"error":"peerId requerido"}`, http.StatusBadRequest)
		return
	}

	peerID := strings.TrimSpace(req.PeerID)
	gs.UnlockPeerClaim(peerID)
	log.Printf("[GitServer] 🔓 Reclamación de peer '%s' desbloqueada por admin", peerID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"unlocked": peerID,
	})
}

// HandleRevokePeer revokes Git access for a specific peerId
func (gs *GitServer) HandleRevokePeer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PeerID) == "" {
		http.Error(w, `{"error":"peerId requerido"}`, http.StatusBadRequest)
		return
	}

	peerID := strings.TrimSpace(req.PeerID)
	gs.RevokePeer(peerID)
	log.Printf("[GitServer] 🚫 Peer '%s' revocado por admin", peerID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"revoked": peerID,
	})
}

// HandleUnrevokePeer restores Git access for a previously revoked peerId
func (gs *GitServer) HandleUnrevokePeer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PeerID) == "" {
		http.Error(w, `{"error":"peerId requerido"}`, http.StatusBadRequest)
		return
	}

	peerID := strings.TrimSpace(req.PeerID)
	gs.UnrevokePeer(peerID)
	log.Printf("[GitServer] 🟢 Acceso restaurado para peer '%s'", peerID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"unrevoked": peerID,
	})
}

// scanRepos scans rootDir for bare repositories (*.git)
func (gs *GitServer) scanRepos() []RepoInfo {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	var repos []RepoInfo
	_ = filepath.Walk(gs.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && strings.HasSuffix(info.Name(), ".git") {
			rel, _ := filepath.Rel(gs.rootDir, path)
			parts := strings.Split(rel, string(os.PathSeparator))
			ns := "default"
			repoName := info.Name()
			if len(parts) > 1 {
				ns = parts[0]
				repoName = strings.Join(parts[1:], "/")
			}

			// Calculate size
			var size int64
			_ = filepath.Walk(path, func(_ string, f os.FileInfo, _ error) error {
				if f != nil && !f.IsDir() {
					size += f.Size()
				}
				return nil
			})

			proto := "http"
			if gs.cfg.EnableTLS {
				proto = "https"
			}
			repoURL := fmt.Sprintf("%s://%s:%d/git/%s/%s", proto, gs.cfg.GetPublicIP(), gs.cfg.HTTPPort, ns, repoName)

			repos = append(repos, RepoInfo{
				Namespace: ns,
				Name:      repoName,
				Path:      path,
				Size:      size,
				URL:       repoURL,
			})
			return filepath.SkipDir
		}
		return nil
	})

	return repos
}
