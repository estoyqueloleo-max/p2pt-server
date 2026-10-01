//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
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

	gs := &GitServer{
		cfg:          cfg,
		authMgr:      authMgr,
		rootDir:      absRootDir,
		revokedPeers: make(map[string]time.Time),
	}

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

// RevokePeer revokes Git access for a specific peerId
func (gs *GitServer) RevokePeer(peerID string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.revokedPeers[strings.TrimSpace(peerID)] = time.Now()
}

// UnrevokePeer restores Git access for a previously revoked peerId
func (gs *GitServer) UnrevokePeer(peerID string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	delete(gs.revokedPeers, strings.TrimSpace(peerID))
}

// IsPeerRevoked checks whether a peerId has been revoked by admin
func (gs *GitServer) IsPeerRevoked(peerID string) bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	_, exists := gs.revokedPeers[strings.TrimSpace(peerID)]
	return exists
}

// GetRevokedPeers returns a slice of currently revoked peerIds
func (gs *GitServer) GetRevokedPeers() []string {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	list := make([]string, 0, len(gs.revokedPeers))
	for p := range gs.revokedPeers {
		list = append(list, p)
	}
	return list
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
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"root_dir":      gs.rootDir,
		"repos":         repos,
		"count":         len(repos),
		"revoked_peers": revoked,
	})
}

// HandleGitCredentials generates a per-peer private repository URL and ephemeral HMAC access token
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
	}

	_ = json.NewEncoder(w).Encode(resp)
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
