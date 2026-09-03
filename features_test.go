package main

import (
	"net"
	"runtime"
	"testing"
)

func TestMDNS_Registration(t *testing.T) {
	mdnsServer, err := StartMDNSServer(9005, 3479, "Pingo Test Instance", "pingo-test")
	if err != nil {
		t.Fatalf("Failed to start mDNS server: %v", err)
	}
	defer mdnsServer.Close()
	t.Log("✅ mDNS server registered and advertised '_pingo._tcp' successfully!")
}

func TestUpdater_VersionComparison(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		newer   bool
	}{
		{"1.0.0", "v1.0.1", true},
		{"1.0.0", "1.1.0", true},
		{"1.0.0", "v2.0.0", true},
		{"1.0.0", "1.0.0", false},
		{"v1.0.0", "1.0.0", false},
		{"1.1.0", "1.0.5", false},
	}

	for _, tt := range tests {
		got := IsNewerVersion(tt.current, tt.latest)
		if got != tt.newer {
			t.Errorf("IsNewerVersion(%q, %q) = %v; want %v", tt.current, tt.latest, got, tt.newer)
		}
	}
	t.Log("✅ Version comparison logic validated!")
}

func TestUpdater_GetBinaryAssetName(t *testing.T) {
	asset := GetBinaryAssetName()
	t.Logf("Current OS/ARCH asset name: %s", asset)

	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && asset != "p2pt-server-linux-amd64" {
		t.Errorf("Expected 'p2pt-server-linux-amd64', got %s", asset)
	}
	t.Log("✅ Binary asset name derivation validated!")
}

func TestIPv6_Classification(t *testing.T) {
	tests := []struct {
		ip       string
		isGlobal bool
	}{
		{"2a0c:5a80:1234:5600::50", true},       // Digi Global Unicast
		{"2001:db8::1", true},                   // Global Unicast doc range
		{"fe80::ba27:ebff:fe12:3456", false},    // Link-Local
		{"fc00::1", false},                      // ULA
		{"fd00:abcd:1234::1", false},            // ULA
		{"::1", false},                          // Loopback
		{"127.0.0.1", false},                    // IPv4 Loopback
		{"192.168.1.50", false},                 // IPv4 Private
		{"::ffff:192.168.1.50", false},          // IPv4-mapped IPv6
	}

	for _, tt := range tests {
		parsed := net.ParseIP(tt.ip)
		if parsed == nil {
			t.Fatalf("Failed to parse IP: %s", tt.ip)
		}
		got := isGlobalUnicastIPv6(parsed)
		if got != tt.isGlobal {
			t.Errorf("isGlobalUnicastIPv6(%q) = %v; want %v", tt.ip, got, tt.isGlobal)
		}
	}
	t.Log("✅ IPv6 Global Unicast filter validated for Digi and global networks!")
}

func TestDuckDNS_DomainFormatting(t *testing.T) {
	if got := cleanDuckDomain("mi-pingo.duckdns.org"); got != "mi-pingo" {
		t.Errorf("cleanDuckDomain = %q; want 'mi-pingo'", got)
	}
	if got := cleanDuckDomain("MI-PINGO"); got != "mi-pingo" {
		t.Errorf("cleanDuckDomain = %q; want 'mi-pingo'", got)
	}
	if got := formatFullDomain("mi-pingo"); got != "mi-pingo.duckdns.org" {
		t.Errorf("formatFullDomain = %q; want 'mi-pingo.duckdns.org'", got)
	}
	t.Log("✅ DuckDNS domain formatting validated!")
}

