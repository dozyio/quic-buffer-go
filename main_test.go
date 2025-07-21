package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
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
		clientToServer: make(chan []byte, 50),
		serverToClient: make(chan []byte, 50),
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
func (t *mockTransport) Inverted() *mockTransportInverted {
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
		require.NoError(t, err) // io.ReadAll returns nil error on successful read to EOF
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
	const dataSize = 1024 * 1024 * 1024 // 10 MB
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
		serverReceivedData, err = io.ReadAll(stream) // Read until EOF
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

	// Wait for the server to finish receiving everything
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
