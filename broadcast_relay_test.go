package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestBroadcastManagerBasics(t *testing.T) {
	bm := NewBroadcastManager(2, []webrtc.ICEServer{})
	if bm.ActiveStreamsCount() != 0 {
		t.Fatalf("expected 0 active streams, got %d", bm.ActiveStreamsCount())
	}

	// 1. Test OPTIONS on WHIP endpoint
	reqOptions := httptest.NewRequest(http.MethodOptions, "/api/whip/test-stream", nil)
	recOptions := httptest.NewRecorder()
	bm.HandleWHIP(recOptions, reqOptions)
	if recOptions.Code != http.StatusOK {
		t.Errorf("expected 200 OK for OPTIONS WHIP, got %d", recOptions.Code)
	}

	// 2. Test GET on WHIP endpoint (Method Not Allowed)
	reqGet := httptest.NewRequest(http.MethodGet, "/api/whip/test-stream", nil)
	recGet := httptest.NewRecorder()
	bm.HandleWHIP(recGet, reqGet)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed for GET WHIP, got %d", recGet.Code)
	}

	// 3. Test POST with empty body (Bad Request)
	reqEmpty := httptest.NewRequest(http.MethodPost, "/api/whip/test-stream", strings.NewReader(""))
	recEmpty := httptest.NewRecorder()
	bm.HandleWHIP(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for empty SDP body, got %d", recEmpty.Code)
	}

	// 4. Test WHEP for non-existing stream (404 Not Found)
	reqWhep := httptest.NewRequest(http.MethodPost, "/api/whep/non-existing", strings.NewReader("v=0..."))
	recWhep := httptest.NewRecorder()
	bm.HandleWHEP(recWhep, reqWhep)
	if recWhep.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for non-existing WHEP stream, got %d", recWhep.Code)
	}
}

func TestBroadcastManager_FullWHIPAndWHEPFlow(t *testing.T) {
	bm := NewBroadcastManager(2, []webrtc.ICEServer{})

	// 1. Publisher creates a local video track
	pubMediaEngine := &webrtc.MediaEngine{}
	if err := pubMediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("failed to register codecs: %v", err)
	}
	pubAPI := webrtc.NewAPI(webrtc.WithMediaEngine(pubMediaEngine))
	pubPC, err := pubAPI.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("failed to create publisher PC: %v", err)
	}
	defer pubPC.Close()

	pubTrack, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video",
		"pingo-test",
	)
	if err != nil {
		t.Fatalf("failed to create local video track: %v", err)
	}

	if _, err := pubPC.AddTrack(pubTrack); err != nil {
		t.Fatalf("failed to add track to publisher: %v", err)
	}

	pubOffer, err := pubPC.CreateOffer(nil)
	if err != nil {
		t.Fatalf("failed to create publisher offer: %v", err)
	}
	if err := pubPC.SetLocalDescription(pubOffer); err != nil {
		t.Fatalf("failed to set local description: %v", err)
	}

	// 2. Publisher ingests via WHIP (POST /api/whip/stream-alpha)
	reqWhip := httptest.NewRequest(http.MethodPost, "/api/whip/stream-alpha", strings.NewReader(pubPC.LocalDescription().SDP))
	reqWhip.Header.Set("Content-Type", "application/sdp")
	recWhip := httptest.NewRecorder()
	bm.HandleWHIP(recWhip, reqWhip)

	if recWhip.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from WHIP, got %d: %s", recWhip.Code, recWhip.Body.String())
	}
	if bm.ActiveStreamsCount() != 1 {
		t.Fatalf("expected 1 active stream, got %d", bm.ActiveStreamsCount())
	}

	pubAnswerSDP := recWhip.Body.String()
	if err := pubPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  pubAnswerSDP,
	}); err != nil {
		t.Fatalf("publisher failed to set remote description answer: %v", err)
	}

	// 3. Subscriber creates recvonly PC
	subMediaEngine := &webrtc.MediaEngine{}
	if err := subMediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("failed to register subscriber codecs: %v", err)
	}
	subAPI := webrtc.NewAPI(webrtc.WithMediaEngine(subMediaEngine))
	subPC, err := subAPI.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("failed to create subscriber PC: %v", err)
	}
	defer subPC.Close()

	if _, err := subPC.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		t.Fatalf("failed to add video transceiver: %v", err)
	}

	subOffer, err := subPC.CreateOffer(nil)
	if err != nil {
		t.Fatalf("failed to create subscriber offer: %v", err)
	}
	if err := subPC.SetLocalDescription(subOffer); err != nil {
		t.Fatalf("failed to set subscriber local description: %v", err)
	}

	// 4. Subscriber subscribes via WHEP (POST /api/whep/stream-alpha)
	reqWhep := httptest.NewRequest(http.MethodPost, "/api/whep/stream-alpha", strings.NewReader(subPC.LocalDescription().SDP))
	reqWhep.Header.Set("Content-Type", "application/sdp")
	recWhep := httptest.NewRecorder()
	bm.HandleWHEP(recWhep, reqWhep)

	if recWhep.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from WHEP, got %d: %s", recWhep.Code, recWhep.Body.String())
	}

	subAnswerSDP := recWhep.Body.String()
	if err := subPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  subAnswerSDP,
	}); err != nil {
		t.Fatalf("subscriber failed to set remote description answer: %v", err)
	}

	// 5. Publisher unpublishes (DELETE /api/whip/stream-alpha)
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/whip/stream-alpha", nil)
	recDel := httptest.NewRecorder()
	bm.HandleWHIP(recDel, reqDel)

	if recDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from DELETE WHIP, got %d", recDel.Code)
	}
	if bm.ActiveStreamsCount() != 0 {
		t.Fatalf("expected 0 active streams after delete, got %d", bm.ActiveStreamsCount())
	}
}
