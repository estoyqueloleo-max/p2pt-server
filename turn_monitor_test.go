package main

import (
	"fmt"
	"testing"
	"time"
)

type dummyAddr struct {
	addr string
}

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return d.addr }

func TestTurnMonitor_AuthAttemptAndSession(t *testing.T) {
	tm := NewTurnMonitor()
	clientAddr := dummyAddr{addr: "192.168.1.50:54321"}

	futureTS := time.Now().Add(24 * time.Hour).Unix()
	user := fmt.Sprintf("%d:pingo-carlos", futureTS)

	tm.RecordAuthAttempt(user, clientAddr, true)

	sessions, activeCount, blockedCount := tm.GetActiveSessions()
	if activeCount != 1 {
		t.Fatalf("Expected 1 active session, got %d", activeCount)
	}
	if blockedCount != 0 {
		t.Errorf("Expected 0 blocked IPs, got %d", blockedCount)
	}
	if len(sessions) != 1 || sessions[0].Username != user {
		t.Errorf("Unexpected session list: %+v", sessions)
	}
	_ = futureTS

	t.Logf("✅ TurnMonitor recorded active session: %+v", sessions[0])
}

func TestTurnMonitor_AbuseDetectionAndRateLimit(t *testing.T) {
	tm := NewTurnMonitor()
	attackerAddr := dummyAddr{addr: "203.0.113.88:12345"}

	if tm.CheckIPBlocked(attackerAddr) {
		t.Fatal("IP should not be blocked initially")
	}

	// Simulate 20 failed auth attempts (brute-force attack)
	for i := 0; i < 20; i++ {
		tm.RecordAuthAttempt("bad-user", attackerAddr, false)
	}

	if !tm.CheckIPBlocked(attackerAddr) {
		t.Error("Expected IP 203.0.113.88 to be blocked after 20 failures")
	}

	_, _, blockedCount := tm.GetActiveSessions()
	if blockedCount != 1 {
		t.Errorf("Expected 1 blocked IP, got %d", blockedCount)
	}

	t.Log("✅ TurnMonitor abuse detection and rate limiting verified!")
}

func TestTurnMonitor_TrafficAccounting(t *testing.T) {
	tm := NewTurnMonitor()
	clientAddr := dummyAddr{addr: "192.168.1.77:40000"}
	user := "pingo-streamer"

	tm.RecordAuthAttempt(user, clientAddr, true)
	tm.RecordPacket(user, "192.168.1.77", 1024*1024) // 1 MB

	sessions, _, _ := tm.GetActiveSessions()
	if len(sessions) != 1 || sessions[0].BytesRelayed != 1024*1024 {
		t.Errorf("Expected 1MB relayed, got %d bytes", sessions[0].BytesRelayed)
	}

	t.Log("✅ Traffic accounting verified successfully!")
}
