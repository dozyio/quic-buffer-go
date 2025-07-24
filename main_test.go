package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// setupTest creates a client and a server connection with an in-memory transport.
// It starts them in goroutines and returns them, along with a teardown function.
func setupTest(t *testing.T) (*Connection, *Connection, func()) {
	clientT, serverT := newInMemoryTransportPair()
	client, err := NewConnection(clientT, true)
	require.NoError(t, err)
	server, err := NewConnection(serverT, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer wg.Done()
		_ = client.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		_ = server.Run(ctx)
	}()

	teardown := func() {
		cancel()
		client.Close(nil)
		server.Close(nil)
		wg.Wait()
	}

	// Manually start the handshake. In a real client, this would happen on Dial.
	client.retransmissionQueue.Add(&wire.PingFrame{})
	client.scheduleSending()

	// Wait for the simplified handshake to complete
	select {
	case <-client.handshakeCompleteChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for client handshake")
	}
	select {
	case <-server.handshakeCompleteChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server handshake")
	}

	return client, server, teardown
}

func TestSendMessage(t *testing.T) {
	client, server, teardown := setupTest(t)
	defer teardown()

	message := []byte("foobar")

	go func() {
		clientStream, err := client.OpenStream(context.Background())
		require.NoError(t, err)
		_, err = clientStream.Write(message)
		require.NoError(t, err)
		err = clientStream.Close()
		require.NoError(t, err)
	}()

	serverStream, err := server.AcceptStream(context.Background())
	require.NoError(t, err)

	receivedData, err := io.ReadAll(serverStream)
	require.NoError(t, err)
	require.Equal(t, message, receivedData)
}

func TestBulkTransfer(t *testing.T) {
	client, server, teardown := setupTest(t)
	defer teardown()

	const dataSize = 100 * 1024 * 1024 // 5 MB
	sendData := make([]byte, dataSize)
	_, err := rand.Read(sendData)
	require.NoError(t, err)

	var receiveWg sync.WaitGroup
	receiveWg.Add(1)
	var receivedData []byte

	go func() {
		defer receiveWg.Done()
		serverStream, err := server.AcceptStream(context.Background())
		require.NoError(t, err)
		receivedData, err = io.ReadAll(serverStream)
		require.NoError(t, err)
	}()

	startTime := time.Now()

	clientStream, err := client.OpenStream(context.Background())
	require.NoError(t, err)
	_, err = clientStream.Write(sendData)
	require.NoError(t, err)
	err = clientStream.Close()
	require.NoError(t, err)

	receiveWg.Wait()

	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()
	log.Printf("[STATS] Transferred %d bytes in %v. Speed: %.2f MB/s", dataSize, duration, mbps)

	require.Equal(t, sendData, receivedData)
}

func TestStreamCancellation(t *testing.T) {
	client, server, teardown := setupTest(t)
	defer teardown()

	clientStream, err := client.OpenStream(context.Background())
	require.NoError(t, err)

	_, err = clientStream.Write([]byte("some data"))
	require.NoError(t, err)

	serverStream, err := server.AcceptStream(context.Background())
	require.NoError(t, err)

	// Simulate canceling the read on the server side
	testErr := errors.New("test cancel")
	serverStream.cancel(testErr)

	// Reading from the canceled stream should return the cancellation error
	_, err = serverStream.Read(make([]byte, 10))
	require.Error(t, err)
	require.ErrorIs(t, err, testErr)
}

func TestFlowControl(t *testing.T) {
	client, server, teardown := setupTest(t)
	defer teardown()

	// Send more data than the initial window and expect it to be received.
	// This implicitly tests that flow control windows are updated.
	const dataSize = protocol.DefaultInitialMaxStreamData + 1024
	sendData := make([]byte, dataSize)
	_, err := rand.Read(sendData)
	require.NoError(t, err)

	var receiveWg sync.WaitGroup
	receiveWg.Add(1)
	var receivedData []byte

	go func() {
		defer receiveWg.Done()
		serverStream, err := server.AcceptStream(context.Background())
		require.NoError(t, err)
		receivedData, err = io.ReadAll(serverStream)
		require.NoError(t, err)
	}()

	clientStream, err := client.OpenStream(context.Background())
	require.NoError(t, err)
	_, err = clientStream.Write(sendData)
	require.NoError(t, err)
	err = clientStream.Close()
	require.NoError(t, err)

	receiveWg.Wait()
	require.Equal(t, sendData, receivedData)
}

func TestMultipleStreams(t *testing.T) {
	client, server, teardown := setupTest(t)
	defer teardown()

	const numStreams = 5
	var clientWg sync.WaitGroup

	for i := 0; i < numStreams; i++ {
		clientWg.Add(1)
		go func(val int) {
			defer clientWg.Done()
			clientStream, err := client.OpenStream(context.Background())
			require.NoError(t, err)
			_, err = clientStream.Write([]byte{byte(val)})
			require.NoError(t, err)
			require.NoError(t, clientStream.Close())
		}(i)
	}

	var serverWg sync.WaitGroup
	receivedMessages := make([][]byte, numStreams)
	for i := 0; i < numStreams; i++ {
		serverWg.Add(1)
		go func(idx int) {
			defer serverWg.Done()
			serverStream, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			data, err := io.ReadAll(serverStream)
			require.NoError(t, err)
			receivedMessages[idx] = data
		}(i)
	}

	clientWg.Wait()
	serverWg.Wait()

	// Check that all messages were received (order is not guaranteed)
	found := make([]bool, numStreams)
	for _, msg := range receivedMessages {
		require.Len(t, msg, 1)
		val := int(msg[0])
		require.False(t, found[val], "should not receive the same message twice")
		found[val] = true
	}
	for i := 0; i < numStreams; i++ {
		require.True(t, found[i], "did not receive message for stream %d", i)
	}
}
