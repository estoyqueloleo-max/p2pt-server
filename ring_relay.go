package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RingPortNode representa un puerto UDP físico específico en el anillo de relay (ej: 7000)
type RingPortNode struct {
	port         uint16
	physicalConn net.PacketConn
	relayAddr    net.Addr
	monitor      *TurnMonitor

	mu          sync.RWMutex
	routes      map[string]*VirtualPacketConn // remotePeerAddr/IP -> virtualConn
	activeConns []*VirtualPacketConn
	closed      bool
}

func (n *RingPortNode) start() {
	buf := make([]byte, 2048)
	for {
		bytesRead, remoteAddr, err := n.physicalConn.ReadFrom(buf)
		if err != nil {
			n.mu.Lock()
			isClosed := n.closed
			n.mu.Unlock()
			if isClosed {
				return
			}
			continue
		}

		if bytesRead <= 0 || remoteAddr == nil {
			continue
		}

		packet := make([]byte, bytesRead)
		copy(packet, buf[:bytesRead])

		n.mu.RLock()
		target := n.findTarget(remoteAddr)
		n.mu.RUnlock()

		if target != nil {
			target.deliver(packet, remoteAddr)
		}
	}
}

func (n *RingPortNode) findTarget(remoteAddr net.Addr) *VirtualPacketConn {
	if remoteAddr == nil {
		return nil
	}
	// 1. Coincidencia exacta por IP:puerto
	if target, ok := n.routes[remoteAddr.String()]; ok {
		return target
	}
	// 2. Coincidencia por IP
	ip := extractIP(remoteAddr.String())
	if target, ok := n.routes[ip]; ok {
		return target
	}
	// 3. Si solo hay 1 conexión virtual activa en este puerto, se le entrega directamente
	if len(n.activeConns) == 1 {
		return n.activeConns[0]
	}
	// 4. Si hay varias pero no conocemos la ruta exacta, entregar a la más reciente
	if len(n.activeConns) > 0 {
		return n.activeConns[len(n.activeConns)-1]
	}
	return nil
}

func (n *RingPortNode) registerRoute(remoteAddrStr string, v *VirtualPacketConn) {
	if remoteAddrStr == "" || v == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[remoteAddrStr] = v
	ip := extractIP(remoteAddrStr)
	if ip != "" {
		n.routes[ip] = v
	}
}

func (n *RingPortNode) unregisterVirtual(v *VirtualPacketConn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, target := range n.routes {
		if target == v {
			delete(n.routes, k)
		}
	}
	for i, conn := range n.activeConns {
		if conn == v {
			n.activeConns = append(n.activeConns[:i], n.activeConns[i+1:]...)
			break
		}
	}
}

// VirtualPacketConn implementa net.PacketConn para una asignación Pion que comparte el socket físico
type VirtualPacketConn struct {
	node      *RingPortNode
	inbound   chan inboundPacket
	closed    atomic.Bool
	closeOnce sync.Once
}

type inboundPacket struct {
	data []byte
	addr net.Addr
}

func (v *VirtualPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	pkt, ok := <-v.inbound
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n = copy(p, pkt.data)
	return n, pkt.addr, nil
}

func (v *VirtualPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if v.closed.Load() {
		return 0, net.ErrClosed
	}
	if addr != nil {
		v.node.registerRoute(addr.String(), v)
	}
	n, err = v.node.physicalConn.WriteTo(p, addr)
	if n > 0 && v.node.monitor != nil {
		v.node.monitor.RecordRelayTraffic(v.node.relayAddr.String(), addr, n)
	}
	return n, err
}

func (v *VirtualPacketConn) Close() error {
	v.closeOnce.Do(func() {
		v.closed.Store(true)
		v.node.unregisterVirtual(v)
		close(v.inbound)
	})
	return nil
}

func (v *VirtualPacketConn) LocalAddr() net.Addr {
	return v.node.relayAddr
}

func (v *VirtualPacketConn) SetDeadline(t time.Time) error      { return nil }
func (v *VirtualPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (v *VirtualPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (v *VirtualPacketConn) deliver(data []byte, addr net.Addr) {
	if v.closed.Load() {
		return
	}
	select {
	case v.inbound <- inboundPacket{data: data, addr: addr}:
		if v.node.monitor != nil {
			v.node.monitor.RecordRelayTraffic(v.node.relayAddr.String(), addr, len(data))
		}
	default:
		// Drop si el buffer está lleno para no congelar el socket físico
	}
}

// RingRelayAddressGenerator gestiona un anillo fijo de puertos UDP de relay para Pion TURN
type RingRelayAddressGenerator struct {
	relayIP      net.IP
	listenIP     string
	minPort      uint16
	maxPort      uint16
	monitor      *TurnMonitor
	mu           sync.Mutex
	ring         []*RingPortNode
	currentIndex int
}

func NewRingRelayAddressGenerator(relayIP net.IP, listenIP string, minPort, maxPort uint16, monitor *TurnMonitor) *RingRelayAddressGenerator {
	if minPort > maxPort {
		minPort, maxPort = maxPort, minPort
	}
	return &RingRelayAddressGenerator{
		relayIP:  relayIP,
		listenIP: listenIP,
		minPort:  minPort,
		maxPort:  maxPort,
		monitor:  monitor,
	}
}

func (r *RingRelayAddressGenerator) Validate() error {
	if r.relayIP == nil {
		return errors.New("RingRelayAddressGenerator: RelayAddress must be set")
	}
	if r.minPort == 0 || r.maxPort == 0 {
		return errors.New("RingRelayAddressGenerator: MinPort and MaxPort must be non-zero")
	}
	return nil
}

func (r *RingRelayAddressGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, nil, fmt.Errorf("network %s not supported", network)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Inicializar nodos del anillo si es la primera llamada
	if len(r.ring) == 0 {
		for port := r.minPort; port <= r.maxPort; port++ {
			node := &RingPortNode{
				port:        port,
				routes:      make(map[string]*VirtualPacketConn),
				activeConns: make([]*VirtualPacketConn, 0),
				monitor:     r.monitor,
			}
			r.ring = append(r.ring, node)
		}
	}

	if len(r.ring) == 0 {
		return nil, nil, errors.New("no ports in relay ring")
	}

	// Seleccionar el siguiente puerto del anillo en Round-Robin
	node := r.ring[r.currentIndex]
	r.currentIndex = (r.currentIndex + 1) % len(r.ring)

	// Asegurar que el socket físico del puerto del anillo esté abierto
	if node.physicalConn == nil {
		listenAddr := fmt.Sprintf("%s:%d", r.listenIP, node.port)
		conn, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to bind physical relay port %d: %w", node.port, err)
		}
		node.physicalConn = conn
		node.relayAddr = &net.UDPAddr{
			IP:   r.relayIP,
			Port: int(node.port),
		}
		go node.start()
	}

	vConn := &VirtualPacketConn{
		node:    node,
		inbound: make(chan inboundPacket, 256),
	}

	node.mu.Lock()
	node.activeConns = append(node.activeConns, vConn)
	node.mu.Unlock()

	return vConn, node.relayAddr, nil
}

func (r *RingRelayAddressGenerator) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	return nil, nil, errors.New("TCP relay not implemented in RingRelayAddressGenerator (use UDP)")
}

func (r *RingRelayAddressGenerator) RegisterPermission(relayAddr net.Addr, peerIP string) {
	if relayAddr == nil || peerIP == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, node := range r.ring {
		if node.relayAddr != nil && node.relayAddr.String() == relayAddr.String() {
			node.mu.Lock()
			if len(node.activeConns) > 0 {
				latest := node.activeConns[len(node.activeConns)-1]
				node.routes[peerIP] = latest
			}
			node.mu.Unlock()
			break
		}
	}
}

func (r *RingRelayAddressGenerator) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, node := range r.ring {
		node.mu.Lock()
		node.closed = true
		if node.physicalConn != nil {
			node.physicalConn.Close()
		}
		for _, v := range node.activeConns {
			v.Close()
		}
		node.mu.Unlock()
	}
}
