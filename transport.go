package main

import (
	"errors"
	"io"
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
	closeOnce sync.Once
	closed    chan struct{}
}

// newInMemoryTransportPair creates a pair of connected in-memory transports.
func newInMemoryTransportPair() (LowerLayerTransport, LowerLayerTransport) {
	ch1 := make(chan []byte, 100) // Buffered channels
	ch2 := make(chan []byte, 100)
	closed := make(chan struct{})

	client := &inMemoryTransport{
		readChan:  ch2,
		writeChan: ch1,
		closed:    closed,
	}

	server := &inMemoryTransport{
		readChan:  ch1,
		writeChan: ch2,
		closed:    closed,
	}

	return client, server
}

func (t *inMemoryTransport) WritePacket(pkt []byte) error {
	select {
	case <-t.closed:
		return errors.New("transport closed")
	default:
	}
	// Make a copy to prevent race conditions if the sender reuses the buffer.
	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)
	select {
	case <-t.closed:
		return errors.New("transport closed")
	case t.writeChan <- pktCopy:
		return nil
	}
}

func (t *inMemoryTransport) ReadPacket() ([]byte, error) {
	select {
	case <-t.closed:
		return nil, errors.New("transport closed")
	case pkt := <-t.readChan:
		return pkt, nil
	}
}

func (t *inMemoryTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil

