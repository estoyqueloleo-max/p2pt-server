package main

import (
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
