package main

import (
	"fmt"
	"log"

	"github.com/grandcat/zeroconf"
)

// MDNSServer manages the local mDNS / Zeroconf advertisement
type MDNSServer struct {
	server *zeroconf.Server
}

// StartMDNSServer announces pingo-server on the local network as '_pingo._tcp'
func StartMDNSServer(httpPort, turnPort int, instanceName, hostName string) (*MDNSServer, error) {
	if instanceName == "" {
		instanceName = "Pingo Server"
	}

	txtRecords := []string{
		"txtvers=1",
		fmt.Sprintf("httpPort=%d", httpPort),
		fmt.Sprintf("turnPort=%d", turnPort),
		"app=pingo",
		"version=1.0.0",
	}

	server, err := zeroconf.Register(
		instanceName,
		"_pingo._tcp",
		"local.",
		httpPort,
		txtRecords,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register mDNS service: %w", err)
	}

	log.Printf("[mDNS] Anunciando servicio local '_pingo._tcp' en puerto %d (Nombre: '%s')", httpPort, instanceName)
	return &MDNSServer{server: server}, nil
}

// Close stops the mDNS server
func (m *MDNSServer) Close() {
	if m != nil && m.server != nil {
		m.server.Shutdown()
		log.Println("[mDNS] Servicio local detenido.")
	}
}
