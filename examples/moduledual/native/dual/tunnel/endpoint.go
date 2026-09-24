package tunnel

import (
	"log"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LinkEndpoint struct {
	dispatcherMu     sync.RWMutex
	dispatcher       stack.NetworkDispatcher
	onOutgoingPacket func([][]byte)
	packetIn         atomic.Uint64
	packetOut        atomic.Uint64
}

func NewLinkEndpoint() *LinkEndpoint {
	return &LinkEndpoint{}
}

// SetOutgoingPacketHandler sets the uplink sink. The callback MUST copy or
// finish using the slice before returning — the view is released immediately after.
func (e *LinkEndpoint) SetOutgoingPacketHandler(fn func([][]byte)) {
	e.onOutgoingPacket = fn
}

func (e *LinkEndpoint) InjectInbound(data []byte) {
	e.packetIn.Add(1)
	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil || len(data) == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUNNEL] recovered from inbound panic (%d bytes): %v", len(data), r)
		}
	}()
	// MakeWithData / NewViewWithData already copies into a pooled chunk.
	// Do NOT append() first — that was a redundant full-packet copy.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
	})
	// Ownership transfers to the stack (HandlePacket / DecRef inside).
	dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
}

func (e *LinkEndpoint) InjectInboundBatch(pkts [][]byte) {
	if len(pkts) == 0 {
		return
	}
	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil {
		return
	}
	for _, data := range pkts {
		if len(data) == 0 {
			continue
		}
		e.packetIn.Add(1)
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[TUNNEL] recovered from inbound panic (%d bytes): %v", len(data), r)
				}
			}()
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
		}()
	}
}

func (e *LinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	handler := e.onOutgoingPacket
	if handler == nil {
		return pkts.Len(), nil
	}
	views := make([]*buffer.View, 0, pkts.Len())
	batch := make([][]byte, 0, pkts.Len())
	for _, pkt := range pkts.AsSlice() {
		e.packetOut.Add(1)
		view := pkt.ToView()
		if view == nil || view.Size() == 0 {
			if view != nil {
				view.Release()
			}
			n++
			continue
		}
		views = append(views, view)
		batch = append(batch, view.AsSlice())
		n++
	}
	if len(batch) > 0 {
		handler(batch)
	}
	for _, view := range views {
		view.Release()
	}
	return n, nil
}

func (e *LinkEndpoint) MTU() uint32 { return 1300 }
func (e *LinkEndpoint) MaxHeaderLength() uint16         { return 0 }
func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress  { return "\x02\x00\x00\x00\x00\x01" }
func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcherMu.Lock()
	e.dispatcher = dispatcher
	e.dispatcherMu.Unlock()
}
func (e *LinkEndpoint) IsAttached() bool {
	e.dispatcherMu.RLock()
	defer e.dispatcherMu.RUnlock()
	return e.dispatcher != nil
}
func (e *LinkEndpoint) Wait()                                   {}
func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *LinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *LinkEndpoint) Close()                                  {}
func (e *LinkEndpoint) SetMTU(uint32)                           {}
func (e *LinkEndpoint) SetLinkAddress(tcpip.LinkAddress)        {}
func (e *LinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (e *LinkEndpoint) SetOnCloseAction(func())                 {}
