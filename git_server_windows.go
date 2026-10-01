//go:build windows

package main

import (
	"net/http"
	"time"
)

type RepoInfo struct {
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size_bytes"`
	LastCommit time.Time `json:"last_commit,omitempty"`
	URL        string    `json:"url"`
}

type GitServer struct{}

func NewGitServer(cfg *Config, authMgr *AuthManager) (*GitServer, error) {
	return &GitServer{}, nil
}

func (gs *GitServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Embedded Git server is not supported on Windows", http.StatusNotImplemented)
}

func (gs *GitServer) HandleListRepos(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"Embedded Git server is not supported on Windows"}`, http.StatusNotImplemented)
}

func (gs *GitServer) HandleGitCredentials(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"Embedded Git server is not supported on Windows"}`, http.StatusNotImplemented)
}

func (gs *GitServer) HandleRevokePeer(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"Embedded Git server is not supported on Windows"}`, http.StatusNotImplemented)
}

func (gs *GitServer) HandleUnrevokePeer(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"Embedded Git server is not supported on Windows"}`, http.StatusNotImplemented)
}

func (gs *GitServer) HandleUnlockPeer(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"Embedded Git server is not supported on Windows"}`, http.StatusNotImplemented)
}

func (gs *GitServer) RevokePeer(peerID string) {}

func (gs *GitServer) UnrevokePeer(peerID string) {}

func (gs *GitServer) UnlockPeerClaim(peerID string) {}

func (gs *GitServer) IsPeerRevoked(peerID string) bool {
	return false
}

func (gs *GitServer) GetRevokedPeers() []string {
	return nil
}

func (gs *GitServer) GetPeerClaim(peerID string) *PeerClaim {
	return nil
}

func (gs *GitServer) GetAllClaims() map[string]*PeerClaim {
	return nil
}

func (gs *GitServer) scanRepos() []RepoInfo {
	return nil
}
