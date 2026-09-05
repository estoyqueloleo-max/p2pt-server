package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// BroadcastStream represents an active broadcast session (1 publisher, N subscribers).
type BroadcastStream struct {
	ID          string
	PublisherPC *webrtc.PeerConnection
	LocalTracks []*webrtc.TrackLocalStaticRTP
	Subscribers map[string]*webrtc.PeerConnection
	CreatedAt   time.Time
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// BroadcastManager manages all active broadcasts.
type BroadcastManager struct {
	streams      map[string]*BroadcastStream
	mu           sync.RWMutex
	maxStreams   int
	webrtcConfig webrtc.Configuration
}

// NewBroadcastManager initializes a new broadcast manager.
func NewBroadcastManager(maxStreams int, iceServers []webrtc.ICEServer) *BroadcastManager {
	if maxStreams <= 0 {
		maxStreams = 2 // Safe default for low-power appliances like Raspberry Pi Zero W
	}
	return &BroadcastManager{
		streams:    make(map[string]*BroadcastStream),
		maxStreams: maxStreams,
		webrtcConfig: webrtc.Configuration{
			ICEServers: iceServers,
		},
	}
}

func (bm *BroadcastManager) SetICEServers(iceServers []webrtc.ICEServer) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.webrtcConfig.ICEServers = iceServers
}

func (bm *BroadcastManager) getWebRTCConfig() webrtc.Configuration {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.webrtcConfig
}

// HandleWHIP processes WHIP ingestion (POST /api/whip/{streamId}) and teardown (DELETE /api/whip/{streamId}).
func (bm *BroadcastManager) HandleWHIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Location")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	streamID := strings.TrimPrefix(r.URL.Path, "/api/whip/")
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		http.Error(w, "stream ID required in path /api/whip/{streamId}", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodDelete {
		bm.closeStream(streamID)
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	bm.mu.Lock()
	if len(bm.streams) >= bm.maxStreams {
		bm.mu.Unlock()
		http.Error(w, fmt.Sprintf("Maximum concurrent broadcast limit (%d) reached", bm.maxStreams), http.StatusServiceUnavailable)
		return
	}

	// If a stream with this ID already exists, close the old one
	if existing, exists := bm.streams[streamID]; exists {
		go existing.Close()
		delete(bm.streams, streamID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream := &BroadcastStream{
		ID:          streamID,
		Subscribers: make(map[string]*webrtc.PeerConnection),
		CreatedAt:   time.Now(),
		ctx:         ctx,
		cancel:      cancel,
	}
	bm.streams[streamID] = stream
	bm.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		bm.closeStream(streamID)
		http.Error(w, "SDP offer body required", http.StatusBadRequest)
		return
	}
	sdpOffer := string(body)

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		bm.closeStream(streamID)
		http.Error(w, fmt.Sprintf("Failed to register codecs: %v", err), http.StatusInternalServerError)
		return
	}

	api := webrtc.NewAPI(webrtc.WithMediaEngine(mediaEngine))
	pc, err := api.NewPeerConnection(bm.getWebRTCConfig())
	if err != nil {
		bm.closeStream(streamID)
		http.Error(w, fmt.Sprintf("Failed to create PeerConnection: %v", err), http.StatusInternalServerError)
		return
	}
	stream.PublisherPC = pc

	pc.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		log.Printf("[Broadcast] New track received for stream %s: %s (%s)", streamID, remoteTrack.ID(), remoteTrack.Codec().MimeType)

		localTrack, err := webrtc.NewTrackLocalStaticRTP(remoteTrack.Codec().RTPCodecCapability, remoteTrack.ID(), remoteTrack.StreamID())
		if err != nil {
			log.Printf("[Broadcast] Error creating local track for stream %s: %v", streamID, err)
			return
		}

		stream.mu.Lock()
		stream.LocalTracks = append(stream.LocalTracks, localTrack)
		// Attach this new track to any existing subscribers
		for _, subPC := range stream.Subscribers {
			if _, err := subPC.AddTrack(localTrack); err != nil {
				log.Printf("[Broadcast] Error adding late track to subscriber: %v", err)
			}
		}
		stream.mu.Unlock()

		// Read RTP packets in loop and broadcast to localTrack
		go func() {
			buf := make([]byte, 1500)
			for {
				select {
				case <-stream.ctx.Done():
					return
				default:
					n, _, readErr := remoteTrack.Read(buf)
					if readErr != nil {
						return
					}
					if _, writeErr := localTrack.Write(buf[:n]); writeErr != nil {
						return
					}
				}
			}
		}()

		// Periodically send PLI / Keyframe requests to remote track to keep video clean
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stream.ctx.Done():
					return
				case <-ticker.C:
					_ = pc.WriteRTCP([]rtcp.Packet{
						&rtcp.PictureLossIndication{MediaSSRC: uint32(remoteTrack.SSRC())},
					})
				}
			}
		}()
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("[Broadcast] Publisher PC for stream %s changed state: %s", streamID, state)
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			bm.closeStream(streamID)
		}
	})

	// Wait for ICE gathering complete before responding so answer contains all candidates
	gatherComplete := webrtc.GatheringCompletePromise(pc)

	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpOffer,
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		bm.closeStream(streamID)
		http.Error(w, fmt.Sprintf("Failed to set remote description: %v", err), http.StatusBadRequest)
		return
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		bm.closeStream(streamID)
		http.Error(w, fmt.Sprintf("Failed to create answer: %v", err), http.StatusInternalServerError)
		return
	}

	if err := pc.SetLocalDescription(answer); err != nil {
		bm.closeStream(streamID)
		http.Error(w, fmt.Sprintf("Failed to set local description: %v", err), http.StatusInternalServerError)
		return
	}

	select {
	case <-gatherComplete:
	case <-time.After(2 * time.Second):
		log.Printf("[Broadcast] ICE gathering timed out after 2s for stream %s, proceeding with available candidates", streamID)
	}

	finalAnswer := pc.LocalDescription()
	w.Header().Set("Content-Type", "application/sdp")
	w.Header().Set("Location", "/api/whip/"+streamID)
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(finalAnswer.SDP))
	log.Printf("[Broadcast] WHIP stream %s created successfully", streamID)
}

// HandleWHEP processes WHEP subscription (POST /api/whep/{streamId}) and teardown.
func (bm *BroadcastManager) HandleWHEP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Location")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected format: api/whep/{streamId} or api/whep/{streamId}/{subscriberId}
	if len(pathParts) < 3 {
		http.Error(w, "stream ID required in path /api/whep/{streamId}", http.StatusBadRequest)
		return
	}
	streamID := pathParts[2]

	bm.mu.RLock()
	stream, exists := bm.streams[streamID]
	bm.mu.RUnlock()

	if !exists || stream == nil {
		http.Error(w, fmt.Sprintf("Stream %s not found", streamID), http.StatusNotFound)
		return
	}

	if r.Method == http.MethodDelete {
		if len(pathParts) >= 4 {
			subID := pathParts[3]
			stream.removeSubscriber(subID)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "SDP offer body required", http.StatusBadRequest)
		return
	}
	sdpOffer := string(body)

	subID := uuid.New().String()

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register codecs: %v", err), http.StatusInternalServerError)
		return
	}

	api := webrtc.NewAPI(webrtc.WithMediaEngine(mediaEngine))
	subPC, err := api.NewPeerConnection(bm.getWebRTCConfig())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create PeerConnection: %v", err), http.StatusInternalServerError)
		return
	}

	stream.mu.RLock()
	for _, localTrack := range stream.LocalTracks {
		if _, err := subPC.AddTrack(localTrack); err != nil {
			log.Printf("[Broadcast] Error adding track to subscriber %s: %v", subID, err)
		}
	}
	stream.mu.RUnlock()

	stream.addSubscriber(subID, subPC)

	subPC.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("[Broadcast] Subscriber %s (stream %s) changed state: %s", subID, streamID, state)
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			stream.removeSubscriber(subID)
		}
	})

	gatherComplete := webrtc.GatheringCompletePromise(subPC)

	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpOffer,
	}
	if err := subPC.SetRemoteDescription(offer); err != nil {
		stream.removeSubscriber(subID)
		http.Error(w, fmt.Sprintf("Failed to set remote description: %v", err), http.StatusBadRequest)
		return
	}

	answer, err := subPC.CreateAnswer(nil)
	if err != nil {
		stream.removeSubscriber(subID)
		http.Error(w, fmt.Sprintf("Failed to create answer: %v", err), http.StatusInternalServerError)
		return
	}

	if err := subPC.SetLocalDescription(answer); err != nil {
		stream.removeSubscriber(subID)
		http.Error(w, fmt.Sprintf("Failed to set local description: %v", err), http.StatusInternalServerError)
		return
	}

	select {
	case <-gatherComplete:
	case <-time.After(2 * time.Second):
		log.Printf("[Broadcast] ICE gathering timed out after 2s for subscriber %s", subID)
	}

	finalAnswer := subPC.LocalDescription()
	w.Header().Set("Content-Type", "application/sdp")
	w.Header().Set("Location", fmt.Sprintf("/api/whep/%s/%s", streamID, subID))
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(finalAnswer.SDP))
	log.Printf("[Broadcast] WHEP subscriber %s subscribed to stream %s", subID, streamID)
}

func (s *BroadcastStream) addSubscriber(subID string, pc *webrtc.PeerConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Subscribers[subID] = pc
}

func (s *BroadcastStream) removeSubscriber(subID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pc, exists := s.Subscribers[subID]; exists {
		_ = pc.Close()
		delete(s.Subscribers, subID)
		log.Printf("[Broadcast] Subscriber %s removed from stream %s", subID, s.ID)
	}
}

func (s *BroadcastStream) Close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.PublisherPC != nil {
		_ = s.PublisherPC.Close()
	}
	for subID, subPC := range s.Subscribers {
		_ = subPC.Close()
		delete(s.Subscribers, subID)
	}
	log.Printf("[Broadcast] Stream %s closed and resources freed", s.ID)
}

func (bm *BroadcastManager) closeStream(streamID string) {
	bm.mu.Lock()
	stream, exists := bm.streams[streamID]
	if exists {
		delete(bm.streams, streamID)
	}
	bm.mu.Unlock()

	if exists && stream != nil {
		stream.Close()
	}
}

// ActiveStreamsCount returns the current count of active broadcasts.
func (bm *BroadcastManager) ActiveStreamsCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.streams)
}
