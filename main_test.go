package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/dozyio/quic-buffer-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// setupTestConnections creates a client and a server, starts them, and returns them.
func setupTestConnections(t *testing.T, ctx context.Context) (*Connection, *Connection) {
	clientTransport, serverTransport := newInMemoryTransportPair()
	var serverErr, clientErr error
	done := make(chan struct{}, 2)

	var server *Connection
	go func() {
		defer func() { done <- struct{}{} }()
		var err error
		server, err = NewConnection(serverTransport, false)
		require.NoError(t, err)
		serverErr = server.Run(ctx)
	}()

	var client *Connection
	go func() {
		defer func() { done <- struct{}{} }()
		var err error
		client, err = NewConnection(clientTransport, true)
		require.NoError(t, err)
		clientErr = client.Run(ctx)
	}()

	t.Cleanup(func() {
		<-done
		<-done
		if clientErr != nil && clientErr != context.Canceled {
			t.Errorf("Client exited with error: %v", clientErr)
		}
		if serverErr != nil && serverErr != context.Canceled {
			t.Errorf("Server exited with error: %v", serverErr)
		}
	})

	time.Sleep(100 * time.Millisecond) // Give time for goroutines to start
	return client, server
}

// performHandshake simulates the initial handshake process.
func performHandshake(t *testing.T, ctx context.Context, client, server *Connection) {
	t.Log("[TEST] Client sending PING to initiate handshake...")
	client.sendQueue <- &wire.PingFrame{}

	t.Log("[TEST] Waiting for handshake to complete for both client and server...")
	handshakeDone := make(chan struct{}, 2)
	go func() {
		select {
		case <-client.handshakeCompleteChan:
			t.Log("[TEST] Client handshake complete.")
			handshakeDone <- struct{}{}
		case <-ctx.Done():
			t.Error("Context cancelled while waiting for client handshake")
		}
	}()
	go func() {
		select {
		case <-server.handshakeCompleteChan:
			t.Log("[TEST] Server handshake complete.")
			handshakeDone <- struct{}{}
		case <-ctx.Done():
			t.Error("Context cancelled while waiting for server handshake")
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-handshakeDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Handshake timeout")
		}
	}
	t.Log("[TEST] Handshake complete for both peers.")
}

func TestTextMessageTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, server := setupTestConnections(t, ctx)
	performHandshake(t, ctx, client, server)

	message := "Hello from the client! This is a test of the custom QUIC-like stack."

	go func() {
		t.Log("[CLIENT] Opening stream...")
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		t.Logf("[CLIENT] Writing: \"%s\"", message)
		_, err = stream.Write([]byte(message))
		require.NoError(t, err)
		require.NoError(t, stream.Close())
		t.Log("[CLIENT] Closed stream writer.")
	}()

	t.Log("[SERVER] Accepting stream...")
	serverStream, err := server.AcceptStream(ctx)
	require.NoError(t, err)

	t.Log("[SERVER] Reading from stream...")
	buffer, err := io.ReadAll(serverStream)
	require.NoError(t, err)

	t.Logf("[SERVER] Received: \"%s\"", string(buffer))
	require.Equal(t, message, string(buffer), "Data mismatch!")
	t.Log("[SUCCESS] Text message transfer confirmed.")
}

func TestBulkBinaryTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Longer timeout for bulk transfer
	defer cancel()
	client, server := setupTestConnections(t, ctx)
	performHandshake(t, ctx, client, server)

	const dataSize = 10 * 1024 * 1024 // 10 MB
	originalData := make([]byte, dataSize)
	_, err := rand.Read(originalData)
	require.NoError(t, err)

	go func() {
		t.Log("[CLIENT] Opening stream for bulk transfer...")
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		t.Logf("[CLIENT] Writing %d bytes...", dataSize)
		_, err = stream.Write(originalData)
		require.NoError(t, err)
		require.NoError(t, stream.Close())
		t.Log("[CLIENT] Finished writing and closed stream.")
	}()

	t.Log("[SERVER] Accepting stream for bulk transfer...")
	serverStream, err := server.AcceptStream(ctx)
	require.NoError(t, err)

	t.Log("[SERVER] Reading from stream...")
	receivedData, err := io.ReadAll(serverStream)
	require.NoError(t, err)

	t.Logf("[SERVER] Received %d bytes.", len(receivedData))
	require.True(t, bytes.Equal(originalData, receivedData), "Bulk data mismatch!")
	t.Log("[SUCCESS] Bulk binary transfer confirmed.")
}
