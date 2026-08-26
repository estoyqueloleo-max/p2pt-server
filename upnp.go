package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
)

// UPnPReport holds the diagnostic status of UPnP and CGNAT detection
type UPnPReport struct {
	Active           bool     `json:"active"`
	RouterName       string   `json:"router_name,omitempty"`
	RouterExternalIP string   `json:"router_external_ip,omitempty"`
	PublicInternetIP string   `json:"public_internet_ip,omitempty"`
	LocalIP          string   `json:"local_ip,omitempty"`
	HasCGNAT         bool     `json:"has_cgnat"`
	MappedPorts      []string `json:"mapped_ports"`
	Message          string   `json:"message"`
	LastChecked      string   `json:"last_checked"`
}

type UPnPManager struct {
	mu           sync.RWMutex
	lastReport   *UPnPReport
	turnPort     int
	httpPort     int
	localIP      string
	publicIP     string
	ipClients    []*internetgateway1.WANIPConnection1
	pppClients   []*internetgateway1.WANPPPConnection1
}

func NewUPnPManager(turnPort, httpPort int, localIP, publicIP string) *UPnPManager {
	return &UPnPManager{
		turnPort: turnPort,
		httpPort: httpPort,
		localIP:  localIP,
		publicIP: publicIP,
		lastReport: &UPnPReport{
			Active:      false,
			Message:     "UPnP not yet scanned",
			LastChecked: time.Now().Format(time.RFC3339),
		},
	}
}

// isPrivateOrCGNAT checks if an IP is in RFC 1918 or RFC 6598 (CGNAT) space
func isPrivateOrCGNAT(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}

	// Check RFC 1918 Private ranges:
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	// Check RFC 6598 (100.64.0.0/10) CGNAT range: 100.64.0.0 - 100.127.255.255
	_, cgnatNet, err := net.ParseCIDR("100.64.0.0/10")
	if err == nil && cgnatNet.Contains(ip) {
		return true
	}

	return false
}

// DiscoverAndMap attempts to discover IGD router and map ports
func (m *UPnPManager) DiscoverAndMap(ctx context.Context) *UPnPReport {
	m.mu.Lock()
	defer m.mu.Unlock()

	report := &UPnPReport{
		Active:           false,
		LocalIP:          m.localIP,
		PublicInternetIP: m.publicIP,
		MappedPorts:      make([]string, 0),
		LastChecked:      time.Now().Format(time.RFC3339),
	}

	// 1. Discover IGD devices via UPnP
	ipClients, _, _ := internetgateway1.NewWANIPConnection1ClientsCtx(ctx)
	pppClients, _, _ := internetgateway1.NewWANPPPConnection1ClientsCtx(ctx)

	m.ipClients = ipClients
	m.pppClients = pppClients

	if len(ipClients) == 0 && len(pppClients) == 0 {
		report.Active = false
		report.Message = "No se detectó ningún router compatible con UPnP/IGD en la red local."
		m.lastReport = report
		return report
	}

	report.Active = true
	var routerExtIP string

	// Try to get external IP from WANIPConnection1 clients
	for _, c := range ipClients {
		extIP, err := c.GetExternalIPAddressCtx(ctx)
		if err == nil && extIP != "" && extIP != "0.0.0.0" {
			routerExtIP = extIP
			report.RouterName = "WANIPConnection1 IGD"
			break
		}
	}

	// Fallback to WANPPPConnection1 clients
	if routerExtIP == "" {
		for _, c := range pppClients {
			extIP, err := c.GetExternalIPAddressCtx(ctx)
			if err == nil && extIP != "" && extIP != "0.0.0.0" {
				routerExtIP = extIP
				report.RouterName = "WANPPPConnection1 IGD"
				break
			}
		}
	}

	report.RouterExternalIP = routerExtIP

	// 2. Evaluate CGNAT
	if routerExtIP != "" {
		if isPrivateOrCGNAT(routerExtIP) {
			report.HasCGNAT = true
		} else if m.publicIP != "" && m.publicIP != routerExtIP {
			// If public IP seen by external services differs from router WAN IP, CGNAT is present
			report.HasCGNAT = true
		}
	}

	// 3. Perform port mappings
	// A) TURN Port UDP
	if m.turnPort > 0 {
		mapped := m.mapPort(ctx, uint16(m.turnPort), "UDP", "Pingo TURN Relay")
		if mapped {
			report.MappedPorts = append(report.MappedPorts, fmt.Sprintf("%d/UDP (TURN)", m.turnPort))
		}
	}

	// B) HTTP Signaling Port TCP
	if m.httpPort > 0 {
		mapped := m.mapPort(ctx, uint16(m.httpPort), "TCP", "Pingo PeerJS HTTP/WS")
		if mapped {
			report.MappedPorts = append(report.MappedPorts, fmt.Sprintf("%d/TCP (Signaling)", m.httpPort))
		}
	}

	if report.HasCGNAT {
		report.Message = fmt.Sprintf("UPnP activo en router (%s), pero tu conexión tiene CGNAT del operador (IP WAN: %s). Se recomienda túnel inverso (Cloudflare/Tailscale).", report.RouterName, report.RouterExternalIP)
	} else if len(report.MappedPorts) > 0 {
		report.Message = fmt.Sprintf("UPnP activo. Puertos abiertos automáticamente en el router: %s. Sin CGNAT (IP Pública: %s).", strings.Join(report.MappedPorts, ", "), report.RouterExternalIP)
	} else {
		report.Message = "UPnP activo en el router pero no se pudieron mapear los puertos automáticamente (verifica permisos en router)."
	}

	m.lastReport = report
	return report
}

func (m *UPnPManager) mapPort(ctx context.Context, port uint16, protocol, desc string) bool {
	// Try IP clients
	for _, c := range m.ipClients {
		err := c.AddPortMappingCtx(ctx, "", port, protocol, port, m.localIP, true, desc, 0)
		if err == nil {
			log.Printf("[UPnP] ✅ Mapeado puerto %d/%s a %s:%d (%s)", port, protocol, m.localIP, port, desc)
			return true
		}
	}

	// Try PPP clients
	for _, c := range m.pppClients {
		err := c.AddPortMappingCtx(ctx, "", port, protocol, port, m.localIP, true, desc, 0)
		if err == nil {
			log.Printf("[UPnP] ✅ Mapeado puerto %d/%s a %s:%d (%s)", port, protocol, m.localIP, port, desc)
			return true
		}
	}

	log.Printf("[UPnP] ⚠️ No se pudo mapear automáticamente el puerto %d/%s", port, protocol)
	return false
}

func (m *UPnPManager) GetReport() *UPnPReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastReport
}
