package main

import (
	"errors"
	"io"
	"net"
	"sync"
)

// LowerLayerTransport is the interface your reliability layer uses to send and
// receive packets. Your custom transport must implement this.
type LowerLayerTransport interface {
	WritePacket(pkt []byte) error
	ReadPacket() ([]byte, error)
	io.Closer
}

// inMemoryTransport is a simple, thread-safe, in-memory transport for testing.
// It uses channels to simulate a network connection between two endpoints.
type inMemoryTransport struct {
	readChan  <-chan []byte
	writeChan chan<- []byte
	closer    *inMemoryCloser
}

// A single closer for a pair of transports
type inMemoryCloser struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newInMemoryCloser() *inMemoryCloser {
	return &inMemoryCloser{closed: make(chan struct{})}
}

func (c *inMemoryCloser) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
}

// newInMemoryTransportPair creates a pair of connected in-memory transports.
func newInMemoryTransportPair() (LowerLayerTransport, LowerLayerTransport) {
	ch1 := make(chan []byte, 100) // Buffered channels
	ch2 := make(chan []byte, 100)
	closer := newInMemoryCloser()

	client := &inMemoryTransport{
		readChan:  ch2,
		writeChan: ch1,
		closer:    closer,
	}

	server := &inMemoryTransport{
		readChan:  ch1,
		writeChan: ch2,
		closer:    closer,
	}

	return client, server
}

// WritePacket is the legacy write method.
func (t *inMemoryTransport) WritePacket(pkt []byte) error {
	return t.Write(pkt)
}

// Write implements the sendConn interface for the new sendQueue.
func (t *inMemoryTransport) Write(p []byte) error {
	select {
	case <-t.closer.closed:
		return errors.New("transport closed")
	default:
	}
	// Make a copy to prevent race conditions if the sender reuses the buffer.
	pktCopy := make([]byte, len(p))
	copy(pktCopy, p)
	select {
	case <-t.closer.closed:
		return errors.New("transport closed")
	case t.writeChan <- pktCopy:
		return nil
	}
}

// WriteTo implements the sendConn interface for sending probe packets.
// For the in-memory transport, we don't need a real address.
func (t *inMemoryTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	err := t.Write(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *inMemoryTransport) ReadPacket() ([]byte, error) {
	select {
	case <-t.closer.closed:
		return nil, errors.New("transport closed")
	case pkt := <-t.readChan:
		return pkt, nil
	}
}

func (t *inMemoryTransport) Close() error {
	t.closer.Close()
	return nil
}
