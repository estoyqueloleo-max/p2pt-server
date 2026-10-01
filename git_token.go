package main

import (
	"crypto/hmac"
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
	msg := fmt.Sprintf("git:%d:%s", expiryUnix, cleanPeer)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%d_%s", expiryUnix, sig)
}

// ValidateGitToken verifies whether a token is valid, unexpired, and matches the specified peerId
func ValidateGitToken(secret, peerID, token string) bool {
	if secret == "" || peerID == "" || token == "" {
		return false
	}

	cleanPeer := strings.TrimSpace(peerID)
	parts := strings.SplitN(token, "_", 2)
	if len(parts) != 2 {
		return false
	}

	expiryUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	// Check expiration
	if time.Now().Unix() > expiryUnix {
		return false
	}

	providedSig := parts[1]
	msg := fmt.Sprintf("git:%d:%s", expiryUnix, cleanPeer)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) == 1
}
