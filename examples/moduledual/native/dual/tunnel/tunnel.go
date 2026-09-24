package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// IPTunnel is a gVisor netstack whose NIC emits/accepts raw IPv4 packets.
// The CSQTT rust engine speaks the same format over localhost UDP.
type IPTunnel struct {
	stack *stack.Stack
	ep    *LinkEndpoint
}

func NewIPTunnel(clientIP net.IP, onOutgoing func([][]byte)) (*IPTunnel, error) {
	ip4 := clientIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("tunnel IP %q is not IPv4", clientIP)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576})
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	cubic := tcpip.CongestionControlOption("cubic")
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &cubic)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)

	ep := NewLinkEndpoint()
	ep.SetOutgoingPacketHandler(onOutgoing)
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}

	addr := tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
	}, stack.AddressProperties{})
	s.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})

	return &IPTunnel{stack: s, ep: ep}, nil
}

func (t *IPTunnel) InjectInbound(data []byte) {
	t.ep.InjectInbound(data)
}

func (t *IPTunnel) InjectInboundBatch(pkts [][]byte) {
	t.ep.InjectInboundBatch(pkts)
}

func (t *IPTunnel) DialTCP(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("DialTCP: %q is not a literal IP", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("DialTCP: IPv6 not supported")
	}
	return gonet.DialContextTCP(ctx, t.stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
		Port: port,
	}, ipv4.ProtocolNumber)
}

func (t *IPTunnel) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() && !dst.Addr().Is4In6() {
		return nil, fmt.Errorf("DialUDP: IPv6 not supported")
	}
	ip4 := dst.Addr().Unmap().As4()
	return gonet.DialUDP(t.stack, nil, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(ip4),
		Port: dst.Port(),
	}, ipv4.ProtocolNumber)
}

func (t *IPTunnel) Close() {
	if t.stack != nil {
		t.stack.Close()
	}
}
