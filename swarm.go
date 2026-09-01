package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// DeriveInfoHash converts a human-readable TopicID into a 20-byte (40 hex chars) info_hash
func DeriveInfoHash(topic string) string {
	cleanTopic := strings.TrimSpace(strings.ToLower(topic))
	if cleanTopic == "" {
		cleanTopic = "pingo-public-mesh"
	}
	h := sha1.New()
	h.Write([]byte("pingo:topic:" + cleanTopic))
	return hex.EncodeToString(h.Sum(nil))
}

type SwarmAnnouncer struct {
	TopicID       string
	InfoHash      string
	PeerID        string
	Config        *Config
	LocalPort     int
	stopChan      chan struct{}
	Trackers      []string
}

func NewSwarmAnnouncer(cfg *Config) *SwarmAnnouncer {
	topic := cfg.TopicID
	if topic == "" {
		topic = "pingo-public-mesh"
	}
	infoHash := DeriveInfoHash(topic)
	peerID := fmt.Sprintf("-PI0100-%s", infoHash[:12])

	trackers := []string{
		fmt.Sprintf("ws://127.0.0.1:%d/tracker", cfg.HTTPPort),
		"wss://tracker.openwebtorrent.com",
		"wss://tracker.btorrent.xyz",
	}

	return &SwarmAnnouncer{
		TopicID:   topic,
		InfoHash:  infoHash,
		PeerID:    peerID,
		Config:    cfg,
		LocalPort: cfg.HTTPPort,
		Trackers:  trackers,
		stopChan:  make(chan struct{}),
	}
}

// Start launches the background announcer
func (s *SwarmAnnouncer) Start() {
	log.Printf("[Swarm] Anunciador P2P activado para Topic '%s' (InfoHash: %s)", s.TopicID, s.InfoHash)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		// Initial announcement after 3 seconds
		time.Sleep(3 * time.Second)
		s.announceAll()

		for {
			select {
			case <-ticker.C:
				s.announceAll()
			case <-s.stopChan:
				return
			}
		}
	}()
}

func (s *SwarmAnnouncer) announceAll() {
	for _, trackerURL := range s.Trackers {
		go s.announceToTracker(trackerURL)
	}
}

func (s *SwarmAnnouncer) announceToTracker(trackerURL string) {
	u, err := url.Parse(trackerURL)
	if err != nil {
		return
	}

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		// Suppress logs for external public trackers if unreachable in test environments
		if strings.Contains(trackerURL, "127.0.0.1") {
			log.Printf("[Swarm] Local tracker dial notice: %v", err)
		}
		return
	}
	defer conn.Close()

	req := TrackerRequest{
		Action:   "announce",
		InfoHash: s.InfoHash,
		PeerID:   s.PeerID,
		Left:     0,
	}

	if err := conn.WriteJSON(req); err != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err == nil {
		var resp TrackerResponse
		if json.Unmarshal(msg, &resp) == nil && resp.Action == "announce" {
			log.Printf("[Swarm] Anuncio confirmado en tracker '%s' (Nodos en topic: %d)", trackerURL, resp.Complete)
		}
	}
}

func (s *SwarmAnnouncer) Stop() {
	close(s.stopChan)
}
