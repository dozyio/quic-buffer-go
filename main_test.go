package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	mrand "math/rand"
	"sync"
	"testing"
	"time"

	"github.com/dozyio/quic-buffer-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// mockTransport is a simple in-memory transport for testing.
type mockTransport struct {
	clientToServer chan []byte
	serverToClient chan []byte
	wg             sync.WaitGroup
	isClosed       bool
	mu             sync.Mutex
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		clientToServer: make(chan []byte, 100), // Increased buffer
		serverToClient: make(chan []byte, 100), // Increased buffer
	}
}

func (t *mockTransport) WritePacket(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isClosed {
		return io.EOF
	}
	t.clientToServer <- p
	return nil
}

func (t *mockTransport) ReadPacket() ([]byte, error) {
	p, ok := <-t.serverToClient
	if !ok {
		return nil, io.EOF
	}
	return p, nil
}

func (t *mockTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.isClosed {
		close(t.clientToServer)
		close(t.serverToClient)
		t.isClosed = true
	}
	return nil
}

// Inverted returns the server's perspective of the transport.
func (t *mockTransport) Inverted() LowerLayerTransport {
	return &mockTransportInverted{parent: t}
}

type mockTransportInverted struct {
	parent *mockTransport
}

func (t *mockTransportInverted) WritePacket(p []byte) error {
	return t.parent.writePacketToServer(p)
}

func (t *mockTransportInverted) ReadPacket() ([]byte, error) {
	return t.parent.readPacketFromServer()
}

func (t *mockTransportInverted) Close() error {
	return t.parent.Close()
}

func (t *mockTransport) writePacketToServer(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isClosed {
		return io.EOF
	}
	t.serverToClient <- p
	return nil
}

func (t *mockTransport) readPacketFromServer() ([]byte, error) {
	p, ok := <-t.clientToServer
	if !ok {
		return nil, io.EOF
	}
	return p, nil
}

// unreliableTransport wraps a mockTransport to simulate latency, jitter, and packet loss.
type unreliableTransport struct {
	transport      LowerLayerTransport
	latency        time.Duration
	jitter         time.Duration
	packetLossRate float64
	r              *mrand.Rand
	mu             sync.Mutex
}

func newUnreliableTransport(transport LowerLayerTransport, latency, jitter time.Duration, packetLossRate float64) *unreliableTransport {
	return &unreliableTransport{
		transport:      transport,
		latency:        latency,
		jitter:         jitter,
		packetLossRate: packetLossRate,
		r:              mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

func (t *unreliableTransport) WritePacket(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Simulate packet loss
	if t.r.Float64() < t.packetLossRate {
		log.Println("[NET] Packet lost")
		return nil // Just drop the packet
	}

	// Simulate latency and jitter
	delay := t.latency
	if t.jitter > 0 {
		delay += time.Duration(t.r.Int63n(int64(t.jitter)))
	}

	// Important: Make a copy of the packet, as the original buffer might be reused.
	pCopy := make([]byte, len(p))
	copy(pCopy, p)

	time.AfterFunc(delay, func() {
		t.transport.WritePacket(pCopy)
	})

	return nil
}

func (t *unreliableTransport) ReadPacket() ([]byte, error) {
	return t.transport.ReadPacket()
}

func (t *unreliableTransport) Close() error {
	return t.transport.Close()
}

func TestTextMessageTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := newMockTransport()
	client, err := NewConnection(transport, true)
	require.NoError(t, err)
	server, err := NewConnection(transport.Inverted(), false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := client.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()
	go func() {
		defer wg.Done()
		err := server.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()

	// Handshake
	log.Println("[TEST] Client sending PING to initiate handshake...")
	client.sendQueue <- &wire.PingFrame{}

	log.Println("[TEST] Waiting for handshake to complete for both client and server...")
	<-client.handshakeCompleteChan
	log.Println("[TEST] Client handshake complete.")
	<-server.handshakeCompleteChan
	log.Println("[TEST] Server handshake complete.")
	log.Println("[TEST] Handshake complete for both peers.")

	// Data transfer
	message := "Hello from the client! This is a test of the custom QUIC-like stack."
	var serverReceivedMessage string
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	go func() {
		defer transferWg.Done()
		log.Println("[SERVER] Accepting stream...")
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		log.Println("[SERVER] Reading from stream...")
		receivedBytes, err := io.ReadAll(stream)
		require.NoError(t, err)
		serverReceivedMessage = string(receivedBytes)
		log.Printf("[SERVER] Received: \"%s\"", serverReceivedMessage)
	}()

	log.Println("[CLIENT] Opening stream...")
	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	log.Printf("[CLIENT] Writing: \"%s\"", message)
	_, err = stream.Write([]byte(message))
	require.NoError(t, err)
	log.Println("[CLIENT] Closed stream writer.")
	require.NoError(t, stream.Close())

	transferWg.Wait()
	require.Equal(t, message, serverReceivedMessage)
	log.Println("[SUCCESS] Text message transfer confirmed.")

	client.Close(nil)
	server.Close(nil)
	wg.Wait()
}

func TestBulkBinaryTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	transport := newMockTransport()
	client, err := NewConnection(transport, true)
	require.NoError(t, err)
	server, err := NewConnection(transport.Inverted(), false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := client.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()
	go func() {
		defer wg.Done()
		err := server.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()

	// Handshake
	log.Println("[TEST] Client sending PING to initiate handshake...")
	client.sendQueue <- &wire.PingFrame{}
	log.Println("[TEST] Waiting for handshake to complete for both client and server...")
	<-client.handshakeCompleteChan
	log.Println("[TEST] Client handshake complete.")
	<-server.handshakeCompleteChan
	log.Println("[TEST] Server handshake complete.")
	log.Println("[TEST] Handshake complete for both peers.")

	// Data transfer
	const dataSize = 10 * 1024 * 1024 // 10 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)

	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	startTime := time.Now()

	// Server goroutine to receive data
	go func() {
		defer transferWg.Done()
		log.Println("[SERVER] Accepting stream for bulk transfer...")
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		log.Println("[SERVER] Reading from stream...")
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err, "Server should not get an error from io.ReadAll")
		log.Println("[SERVER] Finished reading.")
	}()

	// Client goroutine to send data
	go func() {
		log.Println("[CLIENT] Opening stream for bulk transfer...")
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		log.Printf("[CLIENT] Writing %d bytes...", dataSize)
		_, err = stream.Write(clientData)
		require.NoError(t, err)
		log.Println("[CLIENT] Finished writing and closed stream.")
		require.NoError(t, stream.Close())
	}()

	transferWg.Wait()

	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()

	log.Printf("[SUCCESS] Bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v.", dataSize, duration)
	log.Printf("[STATS] Speed: %.2f MB/s", mbps)

	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData))

	client.Close(nil)
	server.Close(nil)
	wg.Wait()
}

func TestUnreliableBulkTransfer(t *testing.T) {
	const (
		latency        = 1 * time.Millisecond
		jitter         = 1 * time.Millisecond
		packetLossRate = 0.05
		dataSize       = 1 * 1024 * 1024
	)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second) // Longer timeout
	defer cancel()

	underlyingTransport := newMockTransport()

	clientTransport := newUnreliableTransport(underlyingTransport, latency, jitter, packetLossRate)
	serverTransport := newUnreliableTransport(underlyingTransport.Inverted(), latency, jitter, packetLossRate)

	client, err := NewConnection(clientTransport, true)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := client.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()
	go func() {
		defer wg.Done()
		err := server.Run(ctx)
		require.True(t, err == nil || err == context.Canceled || err == context.DeadlineExceeded || errors.Is(err, io.EOF))
	}()

	// Handshake
	log.Println("[TEST] Client sending PING to initiate handshake (unreliable)...")
	client.sendQueue <- &wire.PingFrame{}
	log.Println("[TEST] Waiting for handshake to complete for both client and server (unreliable)...")
	<-client.handshakeCompleteChan
	log.Println("[TEST] Client handshake complete (unreliable).")
	<-server.handshakeCompleteChan
	log.Println("[TEST] Server handshake complete (unreliable).")
	log.Println("[TEST] Handshake complete for both peers (unreliable).")

	// Data transfer
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)

	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	startTime := time.Now()

	// Server goroutine
	go func() {
		defer transferWg.Done()
		log.Println("[SERVER] Accepting stream for unreliable bulk transfer...")
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		log.Println("[SERVER] Reading from stream (unreliable)...")
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err)
		log.Println("[SERVER] Finished reading (unreliable).")
	}()

	// Client goroutine
	go func() {
		log.Println("[CLIENT] Opening stream for unreliable bulk transfer...")
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		log.Printf("[CLIENT] Writing %d bytes (unreliable)...", dataSize)
		_, err = stream.Write(clientData)
		require.NoError(t, err)
		log.Println("[CLIENT] Finished writing and closed stream (unreliable).")
		require.NoError(t, stream.Close())
	}()

	transferWg.Wait()

	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()

	log.Printf("[SUCCESS] Unreliable bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v over an unreliable network.", dataSize, duration)
	log.Printf("[STATS] Effective Speed: %.2f MB/s", mbps)

	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData))

	client.Close(nil)
	server.Close(nil)
	wg.Wait()
}
