package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GetEnvConfigPath returns the primary configuration file path
func GetEnvConfigPath() string {
	if custom := os.Getenv("PINGO_CONFIG_PATH"); custom != "" {
		return custom
	}
	// Check if running on Alpine / Appliance
	if _, err := os.Stat("/etc/p2pt.env"); err == nil {
		return "/etc/p2pt.env"
	}
	// Check if /etc is writable (root)
	if os.Geteuid() == 0 {
		return "/etc/p2pt.env"
	}
	return "./pingo.env"
}

// LoadEnvFile reads key-value pairs from a file and sets them in os.Getenv if currently unset
func LoadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"'`)
			if os.Getenv(k) == "" {
				_ = os.Setenv(k, v)
			}
		}
	}
}

// SaveConfigToEnv persists current configuration to .env format
func SaveConfigToEnv(cfg *Config) error {
	targetPath := GetEnvConfigPath()
	dir := filepath.Dir(targetPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	content := fmt.Sprintf(`# Pingo Server Environment Configuration
# Generated automatically by Setup Wizard / Dashboard

PORT=%d
TURN_PORT=%d
PUBLIC_IP=%s
TOPIC_ID=%s
DUCKDNS_DOMAIN=%s
DUCKDNS_TOKEN=%s
ENABLE_UPNP=%t
ENABLE_MDNS=%t
AUTO_UPDATE=%t
TURN_USER=%s
TURN_PASS=%s
TURN_REALM=%s
TURN_STATIC_AUTH_SECRET=%s
ADMIN_PASSWORD=%s
ALLOW_WAN_DASHBOARD=%t
`,
		cfg.HTTPPort,
		cfg.TURNPort,
		cfg.PublicIP,
		cfg.TopicID,
		cfg.DuckDomain,
		cfg.DuckToken,
		cfg.EnableUPnP,
		cfg.EnableMDNS,
		cfg.EnableAutoUpdate,
		cfg.Username,
		cfg.Password,
		cfg.Realm,
		cfg.AuthSecret,
		cfg.AdminPassword,
		cfg.AllowWANDash,
	)

	err := os.WriteFile(targetPath, []byte(strings.TrimSpace(content)+"\n"), 0644)
	if err == nil && targetPath == "/etc/p2pt.env" {
		go func() {
			_ = exec.Command("mount", "-o", "remount,rw", "/media/mmcblk0p1").Run()
			_ = exec.Command("/sbin/lbu", "commit", "-d", "mmcblk0p1").Run()
			_ = exec.Command("mount", "-o", "remount,ro", "/media/mmcblk0p1").Run()
		}()
	}
	return err
}
