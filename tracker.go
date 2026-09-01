package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebTorrent Tracker Message structures
type TrackerRequest struct {
	Action     string          `json:"action"`
	InfoHash   string          `json:"info_hash"`
	PeerID     string          `json:"peer_id"`
	Offers     []TrackerOffer  `json:"offers,omitempty"`
	Answer     *TrackerAnswer  `json:"answer,omitempty"`
	ToPeerID   string          `json:"to_peer_id,omitempty"`
	OfferID    string          `json:"offer_id,omitempty"`
	NumWant    int             `json:"numwant,omitempty"`
	Left       int64           `json:"left,omitempty"`
	Uploaded   int64           `json:"uploaded,omitempty"`
	Downloaded int64           `json:"downloaded,omitempty"`
	Event      string          `json:"event,omitempty"`
}

type TrackerOffer struct {
	OfferID string          `json:"offer_id"`
	Offer   json.RawMessage `json:"offer"`
}

type TrackerAnswer struct {
	OfferID string          `json:"offer_id"`
	Answer  json.RawMessage `json:"answer"`
}

type TrackerResponse struct {
	Action     string          `json:"action,omitempty"`
	InfoHash   string          `json:"info_hash,omitempty"`
	Interval   int             `json:"interval,omitempty"`
	Complete   int             `json:"complete,omitempty"`
	Incomplete int             `json:"incomplete,omitempty"`
	PeerID     string          `json:"peer_id,omitempty"`
	OfferID    string          `json:"offer_id,omitempty"`
	Offer      json.RawMessage `json:"offer,omitempty"`
	Answer     json.RawMessage `json:"answer,omitempty"`
	Failure    string          `json:"failure reason,omitempty"`
}

type PeerSession struct {
	PeerID   string
	Conn     *websocket.Conn
	LastSeen time.Time
	SendMu   sync.Mutex
}

func (p *PeerSession) Send(v interface{}) error {
	p.SendMu.Lock()
	defer p.SendMu.Unlock()
	return p.Conn.WriteJSON(v)
}

type WebTorrentTracker struct {
	swarms   map[string]map[string]*PeerSession // info_hash -> peer_id -> session
	peers    map[string]map[string]bool         // peer_id -> set of info_hashes
	mu       sync.RWMutex
	upgrader websocket.Upgrader
}

func NewWebTorrentTracker() *WebTorrentTracker {
	return &WebTorrentTracker{
		swarms: make(map[string]map[string]*PeerSession),
		peers:  make(map[string]map[string]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (t *WebTorrentTracker) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := t.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Tracker] WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	var currentPeerID string
	peerSession := &PeerSession{
		Conn:     conn,
		LastSeen: time.Now(),
	}

	defer func() {
		if currentPeerID != "" {
			t.removePeer(currentPeerID)
		}
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var req TrackerRequest
		if err := json.Unmarshal(message, &req); err != nil {
			_ = peerSession.Send(TrackerResponse{Failure: "malformed JSON request"})
			continue
		}

		if req.PeerID != "" {
			currentPeerID = req.PeerID
			peerSession.PeerID = req.PeerID
		}

		switch req.Action {
		case "announce":
			t.handleAnnounce(peerSession, &req)
		case "scrape":
			t.handleScrape(peerSession, &req)
		default:
			// Forwarding WebRTC offer / answer
			if req.ToPeerID != "" {
				t.forwardSignal(peerSession, &req)
			}
		}
	}
}

func (t *WebTorrentTracker) handleAnnounce(session *PeerSession, req *TrackerRequest) {
	if req.InfoHash == "" || req.PeerID == "" {
		_ = session.Send(TrackerResponse{Failure: "missing info_hash or peer_id"})
		return
	}

	t.mu.Lock()
	if _, exists := t.swarms[req.InfoHash]; !exists {
		t.swarms[req.InfoHash] = make(map[string]*PeerSession)
	}
	t.swarms[req.InfoHash][req.PeerID] = session

	if _, exists := t.peers[req.PeerID]; !exists {
		t.peers[req.PeerID] = make(map[string]bool)
	}
	t.peers[req.PeerID][req.InfoHash] = true

	swarmSize := len(t.swarms[req.InfoHash])
	t.mu.Unlock()

	// Respond with tracker stats
	_ = session.Send(TrackerResponse{
		Action:     "announce",
		InfoHash:   req.InfoHash,
		Interval:   120,
		Complete:   swarmSize,
		Incomplete: 0,
	})

	// If offers were included, distribute them to other peers in the swarm
	if len(req.Offers) > 0 {
		t.distributeOffers(session, req)
	}
}

func (t *WebTorrentTracker) distributeOffers(session *PeerSession, req *TrackerRequest) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	swarm, exists := t.swarms[req.InfoHash]
	if !exists {
		return
	}

	offerIdx := 0
	for peerID, targetSession := range swarm {
		if peerID == req.PeerID {
			continue
		}
		if offerIdx >= len(req.Offers) {
			break
		}

		offer := req.Offers[offerIdx]
		_ = targetSession.Send(TrackerResponse{
			InfoHash: req.InfoHash,
			PeerID:   req.PeerID,
			OfferID:  offer.OfferID,
			Offer:    offer.Offer,
		})
		offerIdx++
	}
}

func (t *WebTorrentTracker) forwardSignal(session *PeerSession, req *TrackerRequest) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if swarm, exists := t.swarms[req.InfoHash]; exists {
		if targetSession, exists := swarm[req.ToPeerID]; exists {
			if req.Answer != nil {
				_ = targetSession.Send(TrackerResponse{
					InfoHash: req.InfoHash,
					PeerID:   session.PeerID,
					OfferID:  req.OfferID,
					Answer:   req.Answer.Answer,
				})
			}
		}
	}
}

func (t *WebTorrentTracker) handleScrape(session *PeerSession, req *TrackerRequest) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	swarmSize := 0
	if swarm, exists := t.swarms[req.InfoHash]; exists {
		swarmSize = len(swarm)
	}

	_ = session.Send(TrackerResponse{
		Action:     "scrape",
		InfoHash:   req.InfoHash,
		Complete:   swarmSize,
		Incomplete: 0,
	})
}

func (t *WebTorrentTracker) removePeer(peerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if hashes, exists := t.peers[peerID]; exists {
		for infoHash := range hashes {
			if swarm, exists := t.swarms[infoHash]; exists {
				delete(swarm, peerID)
				if len(swarm) == 0 {
					delete(t.swarms, infoHash)
				}
			}
		}
		delete(t.peers, peerID)
	}
}

func (t *WebTorrentTracker) SwarmCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.swarms)
}
