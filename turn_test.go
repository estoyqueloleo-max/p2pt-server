package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

// Helper to create a test TURN server on dynamic ephemeral ports
func setupTestTURNServer(t *testing.T, username, password, authSecret, realm string) (*turn.Server, net.PacketConn, int) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on UDP packet: %v", err)
	}

	serverPort := conn.LocalAddr().(*net.UDPAddr).Port

	server, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(u string, r string, srcAddr net.Addr) ([]byte, bool) {
			if u == username {
				return turn.GenerateAuthKey(u, r, password), true
			}
			if authSecret != "" {
				parts := strings.Split(u, ":")
				if len(parts) >= 2 {
					mac := hmac.New(sha1.New, []byte(authSecret))
					mac.Write([]byte(u))
					expectedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))
					return turn.GenerateAuthKey(u, r, expectedPassword), true
				}
				return turn.GenerateAuthKey(u, r, authSecret), true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: conn,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "127.0.0.1",
					MinPort:      50000,
					MaxPort:      50100,
				},
			},
		},
	})
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to create test TURN server: %v", err)
	}

	return server, conn, serverPort
}

func TestTURN_STUNBinding(t *testing.T) {
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", "secret123", "pingo")
	defer server.Close()
	defer conn.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client listener: %v", err)
	}
	defer clientConn.Close()

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		Conn:           clientConn,
	})
	if err != nil {
		t.Fatalf("Failed to create TURN client: %v", err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		t.Fatalf("Failed to start client listening: %v", err)
	}

	mappedAddr, err := client.SendBindingRequest()
	if err != nil {
		t.Fatalf("STUN Binding Request failed: %v", err)
	}

	clientUDPAddr := clientConn.LocalAddr().(*net.UDPAddr)
	if mappedAddr.String() != clientUDPAddr.String() {
		t.Errorf("Expected mapped address %v, got %v", clientUDPAddr, mappedAddr)
	}
	t.Logf("✅ STUN Binding Request successful! Reflected Addr: %s", mappedAddr.String())
}

func TestTURN_AllocationSuccess(t *testing.T) {
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", "secret123", "pingo")
	defer server.Close()
	defer conn.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client listener: %v", err)
	}
	defer clientConn.Close()

	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		Conn:           clientConn,
		Username:       "pingo",
		Password:       "pingosecret",
		Realm:          "pingo",
	})
	if err != nil {
		t.Fatalf("Failed to create TURN client: %v", err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		t.Fatalf("Failed to listen client: %v", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("TURN Allocate failed: %v", err)
	}
	defer relayConn.Close()

	relayedAddr := relayConn.LocalAddr()
	t.Logf("✅ TURN Allocation succeeded! Relayed Addr: %s", relayedAddr.String())

	if relayedAddr.Network() != "udp" {
		t.Errorf("Expected udp network, got %s", relayedAddr.Network())
	}
}

func TestTURN_AllocationFailureWithBadCredentials(t *testing.T) {
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", "secret123", "pingo")
	defer server.Close()
	defer conn.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client listener: %v", err)
	}
	defer clientConn.Close()

	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		Conn:           clientConn,
		Username:       "pingo",
		Password:       "wrong_password_test",
		Realm:          "pingo",
	})
	if err != nil {
		t.Fatalf("Failed to create TURN client: %v", err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		t.Fatalf("Failed to listen client: %v", err)
	}

	_, err = client.Allocate()
	if err == nil {
		t.Fatalf("Expected TURN Allocate to fail with invalid password, but it succeeded!")
	}
	t.Logf("✅ TURN correctly rejected invalid credentials: %v", err)
}

func TestTURN_AllocationWithHMACStaticSecret(t *testing.T) {
	authSecret := "pingo-super-secret-hmac"
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", authSecret, "pingo")
	defer server.Close()
	defer conn.Close()

	// Generate time-windowed username & HMAC password as Coturn / Cloudflare TURN REST API does
	timestamp := time.Now().Add(1 * time.Hour).Unix()
	username := fmt.Sprintf("%d:testuser", timestamp)

	mac := hmac.New(sha1.New, []byte(authSecret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client listener: %v", err)
	}
	defer clientConn.Close()

	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: fmt.Sprintf("127.0.0.1:%d", port),
		Conn:           clientConn,
		Username:       username,
		Password:       password,
		Realm:          "pingo",
	})
	if err != nil {
		t.Fatalf("Failed to create TURN client: %v", err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		t.Fatalf("Failed to listen client: %v", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("TURN Allocate with HMAC secret failed: %v", err)
	}
	defer relayConn.Close()

	t.Logf("✅ TURN Allocation with HMAC REST API succeeded! Relayed Addr: %s", relayConn.LocalAddr().String())
}

func TestTURN_RelayPacketTransmissionAndEcho(t *testing.T) {
	server, conn, port := setupTestTURNServer(t, "pingo", "pingosecret", "secret123", "pingo")
	defer server.Close()
	defer conn.Close()

	// 1. Peer A (TURN Client)
	clientConnA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client A listener: %v", err)
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
		t.Fatalf("Failed to create TURN client A: %v", err)
	}
	defer clientA.Close()

	if err := clientA.Listen(); err != nil {
		t.Fatalf("Failed to listen client A: %v", err)
	}

	relayConnA, err := clientA.Allocate()
	if err != nil {
		t.Fatalf("Client A Allocate failed: %v", err)
	}
	defer relayConnA.Close()

	relayedAddrA := relayConnA.LocalAddr()

	// 2. Peer B (Simulating remote peer)
	peerBConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create Peer B listener: %v", err)
	}
	defer peerBConn.Close()
	peerBAddr := peerBConn.LocalAddr().(*net.UDPAddr)

	// 3. Client A creates permission to send/receive to/from Peer B
	if err := clientA.CreatePermission(peerBAddr); err != nil {
		t.Fatalf("Failed to create permission for Peer B: %v", err)
	}

	// 4. Client A sends data through Relay to Peer B
	testMessage := "PINGO_RELAY_TEST_PACKET_HELLO_WORLD"
	_, err = relayConnA.WriteTo([]byte(testMessage), peerBAddr)
	if err != nil {
		t.Fatalf("Failed to write data from Relay to Peer B: %v", err)
	}

	// 5. Peer B receives packet from the Relayed Address
	buf := make([]byte, 1500)
	peerBConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, fromAddr, err := peerBConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Peer B failed to read relayed packet: %v", err)
	}

	receivedMsg := string(buf[:n])
	if receivedMsg != testMessage {
		t.Fatalf("Expected message '%s', got '%s'", testMessage, receivedMsg)
	}

	// Confirm that the source packet IP:port seen by Peer B is indeed the TURN Relayed Address
	if fromAddr.String() != relayedAddrA.String() {
		t.Errorf("Expected packet to arrive from Relay Addr %s, but came from %s", relayedAddrA.String(), fromAddr.String())
	}
	t.Logf("✅ Peer B received message '%s' from Relay %s", receivedMsg, fromAddr.String())

	// 6. Peer B replies back to Relay Address
	replyMessage := "PINGO_RELAY_REPLY_PONG"
	_, err = peerBConn.WriteTo([]byte(replyMessage), relayedAddrA)
	if err != nil {
		t.Fatalf("Peer B failed to reply to Relay: %v", err)
	}

	// 7. Client A receives reply on relayConnA
	bufA := make([]byte, 1500)
	relayConnA.SetReadDeadline(time.Now().Add(3 * time.Second))
	nA, fromPeerB, err := relayConnA.ReadFrom(bufA)
	if err != nil {
		t.Fatalf("Client A failed to receive reply from Peer B through relay: %v", err)
	}

	if string(bufA[:nA]) != replyMessage {
		t.Fatalf("Expected reply '%s', got '%s'", replyMessage, string(bufA[:nA]))
	}
	t.Logf("✅ Client A received reply '%s' from %s via TURN Relay!", string(bufA[:nA]), fromPeerB.String())
}
