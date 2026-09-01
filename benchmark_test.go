package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

// TestTURNBenchmark_ThroughputAndLoss measures UDP packet relay throughput, loss rate, and latency
func TestTURNBenchmark_ThroughputAndLoss(t *testing.T) {
	// Setup TURN Server
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", "secret123", "pingo")
	defer server.Close()
	defer conn.Close()

	// 1. Client A (Sender via TURN Relay)
	clientConnA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create Client A listener: %v", err)
	}
	defer clientConnA.Close()

	clientA, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		Conn:           clientConnA,
		Username:       "pingo",
		Password:       "pingosecret",
		Realm:          "pingo",
	})
	if err != nil {
		t.Fatalf("Failed to create TURN Client A: %v", err)
	}
	defer clientA.Close()

	if err := clientA.Listen(); err != nil {
		t.Fatalf("Failed to listen Client A: %v", err)
	}

	relayConnA, err := clientA.Allocate()
	if err != nil {
		t.Fatalf("Client A Allocate failed: %v", err)
	}
	defer relayConnA.Close()
	relayedAddrA := relayConnA.LocalAddr()

	// 2. Peer B (Receiver)
	peerBConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create Peer B listener: %v", err)
	}
	defer peerBConn.Close()
	peerBAddr := peerBConn.LocalAddr().(*net.UDPAddr)

	// Authorize Peer B
	if err := clientA.CreatePermission(peerBAddr); err != nil {
		t.Fatalf("Failed to create permission: %v", err)
	}

	// 3. Benchmark Parameters (Simulating Video Stream: 1200 byte packets)
	packetSize := 1200
	packetCount := 2000
	payload := make([]byte, packetSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var receivedCount uint64
	var totalBytesReceived uint64
	stopReceiver := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	// Receiver Goroutine
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopReceiver:
				return
			default:
				peerBConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, _, err := peerBConn.ReadFrom(buf)
				if err == nil && n > 0 {
					atomic.AddUint64(&receivedCount, 1)
					atomic.AddUint64(&totalBytesReceived, uint64(n))
				}
			}
		}
	}()

	// 4. Send Packet Stream
	t.Logf("🚀 Starting Relay Benchmark: Sending %d packets (%d bytes each)...", packetCount, packetSize)
	startTime := time.Now()

	for i := 0; i < packetCount; i++ {
		_, err := relayConnA.WriteTo(payload, peerBAddr)
		if err != nil {
			t.Errorf("Error writing packet %d: %v", i, err)
			break
		}
		// Small pacing (10 microseconds) to emulate smooth media stream
		time.Sleep(10 * time.Microsecond)
	}

	sendDuration := time.Since(startTime)
	// Wait a moment for trailing in-flight packets
	time.Sleep(200 * time.Millisecond)
	close(stopReceiver)
	wg.Wait()

	totalDuration := time.Since(startTime)
	received := atomic.LoadUint64(&receivedCount)
	bytesRecv := atomic.LoadUint64(&totalBytesReceived)

	lossPct := float64(packetCount-int(received)) / float64(packetCount) * 100
	mbps := (float64(bytesRecv) * 8.0) / (totalDuration.Seconds() * 1000000.0)
	throughputMBs := (float64(bytesRecv) / (1024.0 * 1024.0)) / totalDuration.Seconds()

	t.Logf("📊 Benchmark Results:")
	t.Logf("   - Packets Sent: %d", packetCount)
	t.Logf("   - Packets Received: %d", received)
	t.Logf("   - Packet Loss: %.2f%%", lossPct)
	t.Logf("   - Duration: %v (Send time: %v)", totalDuration, sendDuration)
	t.Logf("   - Throughput: %.2f MB/s (%.2f Mbps)", throughputMBs, mbps)
	t.Logf("   - Relayed Addr: %s", relayedAddrA.String())

	if lossPct > 5.0 {
		t.Fatalf("Packet loss was too high (%.2f%% > 5.0%%)", lossPct)
	}
	t.Logf("✅ Benchmark Passed with excellent performance on Pion TURN!")
}
