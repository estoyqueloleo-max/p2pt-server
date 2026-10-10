package main

import (
	"net"

	"github.com/pion/turn/v4"
)

// MeteredPacketConn wraps a net.PacketConn and notifies TurnMonitor of all transferred bytes
type MeteredPacketConn struct {
	net.PacketConn
	monitor    *TurnMonitor
	isRelay    bool
	relayAddr  string
}

func NewMeteredPacketConn(conn net.PacketConn, tm *TurnMonitor, isRelay bool) *MeteredPacketConn {
	relayStr := ""
	if conn != nil && conn.LocalAddr() != nil {
		relayStr = conn.LocalAddr().String()
	}
	return &MeteredPacketConn{
		PacketConn: conn,
		monitor:    tm,
		isRelay:    isRelay,
		relayAddr:  relayStr,
	}
}

func (m *MeteredPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = m.PacketConn.ReadFrom(p)
	if n > 0 && m.monitor != nil {
		if m.isRelay {
			m.monitor.RecordRelayTraffic(m.relayAddr, addr, n)
		} else {
			m.monitor.RecordRawTraffic(addr, n)
		}
	}
	return n, addr, err
}

func (m *MeteredPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = m.PacketConn.WriteTo(p, addr)
	if n > 0 && m.monitor != nil {
		if m.isRelay {
			m.monitor.RecordRelayTraffic(m.relayAddr, addr, n)
		} else {
			m.monitor.RecordRawTraffic(addr, n)
		}
	}
	return n, err
}

// MeteredRelayAddressGenerator wraps turn.RelayAddressGenerator to track bytes on allocated relay sockets
type MeteredRelayAddressGenerator struct {
	turn.RelayAddressGenerator
	monitor *TurnMonitor
}

func NewMeteredRelayAddressGenerator(generator turn.RelayAddressGenerator, tm *TurnMonitor) *MeteredRelayAddressGenerator {
	return &MeteredRelayAddressGenerator{
		RelayAddressGenerator: generator,
		monitor:                tm,
	}
}

func (g *MeteredRelayAddressGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}
	metered := NewMeteredPacketConn(conn, g.monitor, true)
	return metered, addr, nil
}

func (g *MeteredRelayAddressGenerator) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	return g.RelayAddressGenerator.AllocateConn(network, requestedPort)
}

func (g *MeteredRelayAddressGenerator) Validate() error {
	return g.RelayAddressGenerator.Validate()
}
