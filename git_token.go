package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GenerateGitToken creates a tamper-proof HMAC-SHA256 ephemeral token for a given peerId and expiration
func GenerateGitToken(secret, peerID string, expiry time.Time) string {
	cleanPeer := strings.TrimSpace(peerID)
	expiryUnix := expiry.Unix()
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	msg := fmt.Sprintf("git:%d:%s:%s", expiryUnix, nonce, cleanPeer)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%d_%s_%s", expiryUnix, nonce, sig)
}

// ValidateGitToken verifies whether a token is valid, unexpired, and matches the specified peerId
func ValidateGitToken(secret, peerID, token string) bool {
	if secret == "" || peerID == "" || token == "" {
		return false
	}

	cleanPeer := strings.TrimSpace(peerID)
	parts := strings.Split(token, "_")
	if len(parts) == 3 {
		expiryUnix, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || time.Now().Unix() > expiryUnix {
			return false
		}
		nonce := parts[1]
		providedSig := parts[2]
		msg := fmt.Sprintf("git:%d:%s:%s", expiryUnix, nonce, cleanPeer)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(msg))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) == 1
	} else if len(parts) == 2 {
		// Backwards compatibility with 2-part tokens (expiry_sig)
		expiryUnix, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || time.Now().Unix() > expiryUnix {
			return false
		}
		providedSig := parts[1]
		msg := fmt.Sprintf("git:%d:%s", expiryUnix, cleanPeer)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(msg))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		return subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) == 1
	}

	return false
}

// HashGitToken computes a SHA-256 hex digest of a token for safe persistent storage
func HashGitToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// PeerClaim represents the claim state of a peer repository
type PeerClaim struct {
	PeerID    string    `json:"peer_id"`
	TokenHash string    `json:"token_hash"`
	ClaimedAt time.Time `json:"claimed_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ClientIP  string    `json:"client_ip,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	Revoked   bool      `json:"revoked"`
}

