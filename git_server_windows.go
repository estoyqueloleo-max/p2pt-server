//go:build windows

package main

import (
	"net/http"
)

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
