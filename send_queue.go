package main

import (
	"net"
)

// sender is the interface for the send queue.
type sender interface {
	Send(p *packetBuffer)
	SendProbe(p *packetBuffer, addr net.Addr)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

// queueEntry represents a packet to be sent.
type queueEntry struct {
	buf *packetBuffer
}

// sendQueue manages the sending of packets.
type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // closed when Close() is called
	runStopped  chan struct{} // closed when the run loop returns
	available   chan struct{}
	conn        sendConn
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

// newSendQueue creates a new send queue.
func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer) {
	select {
	case h.queue <- queueEntry{buf: p}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

// SendProbe sends a probe packet.
func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr) {
	h.conn.WriteTo(p.Data, addr)
}

// WouldBlock returns true if the send queue is full.
func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

// Available returns a channel that is closed when the send queue has space.
func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

// Run is the main loop of the send queue.
func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			if err := h.conn.Write(e.buf.Data); err != nil {
				if !isSendMsgSizeErr(err) {
					return err
				}
			}
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

// Close gracefully closes the send queue.
func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
