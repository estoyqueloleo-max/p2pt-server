package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestTracker_DeriveInfoHash(t *testing.T) {
	hash1 := DeriveInfoHash("amigos-valencia")
	hash2 := DeriveInfoHash("  AMIGOS-VALENCIA  ")
	hashDefault := DeriveInfoHash("")

	if len(hash1) != 40 {
		t.Errorf("Expected 40 hex characters for info_hash, got len=%d (%s)", len(hash1), hash1)
	}

	if hash1 != hash2 {
		t.Errorf("Expected case-insensitive and trimmed hashing match, got %s != %s", hash1, hash2)
	}

	if hashDefault == "" || len(hashDefault) != 40 {
		t.Errorf("Expected default hash for empty topic, got %s", hashDefault)
	}

	t.Logf("✅ Topic 'amigos-valencia' derived to info_hash: %s", hash1)
}

func TestTracker_AnnounceAndScrape(t *testing.T) {
	tracker := NewWebTorrentTracker()
	server := httptest.NewServer(http.HandlerFunc(tracker.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebTorrent tracker: %v", err)
	}
	defer conn.Close()

	topicHash := DeriveInfoHash("test-topic-swarm")
	peerID := "-PI0100-testpeer1234"

	// 1. Send Announce
	announceReq := TrackerRequest{
		Action:   "announce",
		InfoHash: topicHash,
		PeerID:   peerID,
		Left:     0,
	}

	if err := conn.WriteJSON(announceReq); err != nil {
		t.Fatalf("Failed to send announce request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read announce response: %v", err)
	}

	var resp TrackerResponse
	if err := json.Unmarshal(msg, &resp); err != nil {
		t.Fatalf("Malformed response from tracker: %v", err)
	}

	if resp.Action != "announce" {
		t.Errorf("Expected action 'announce', got '%s'", resp.Action)
	}
	if resp.Complete != 1 {
		t.Errorf("Expected complete=1, got %d", resp.Complete)
	}

	t.Logf("✅ Tracker successfully processed announce for peer '%s' (Swarm count: %d)", peerID, resp.Complete)

	// 2. Send Scrape
	scrapeReq := TrackerRequest{
		Action:   "scrape",
		InfoHash: topicHash,
	}
	if err := conn.WriteJSON(scrapeReq); err != nil {
		t.Fatalf("Failed to send scrape request: %v", err)
	}

	_, msgScrape, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read scrape response: %v", err)
	}

	var respScrape TrackerResponse
	if err := json.Unmarshal(msgScrape, &respScrape); err != nil {
		t.Fatalf("Malformed scrape response: %v", err)
	}

	if respScrape.Action != "scrape" || respScrape.Complete != 1 {
		t.Errorf("Scrape verification failed: %+v", respScrape)
	}

	t.Log("✅ Tracker scrape verified successfully!")
}
