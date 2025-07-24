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
	"sync/atomic"
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
		clientToServer: make(chan []byte, 100),
		serverToClient: make(chan []byte, 100),
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

// adverseTransport wraps a transport to simulate latency, loss, duplication, and reordering.
type adverseTransport struct {
	underlying    LowerLayerTransport
	latency       time.Duration
	jitter        time.Duration
	lossRate      float64
	duplicateRate float64
	reorderRate   float64
	r             *mrand.Rand
	randLock      sync.Mutex
	reorderBuffer [][]byte
	reorderLock   sync.Mutex
	wg            sync.WaitGroup
	isClosed      bool
	mu            sync.Mutex
	packetCounter atomic.Int64
}

func newAdverseTransport(underlying LowerLayerTransport, latency, jitter time.Duration, loss, duplicate, reorder float64) *adverseTransport {
	return &adverseTransport{
		underlying:    underlying,
		latency:       latency,
		jitter:        jitter,
		lossRate:      loss,
		duplicateRate: duplicate,
		reorderRate:   reorder,
		r:             mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

func (t *adverseTransport) WritePacket(p []byte) error {
	t.mu.Lock()
	if t.isClosed {
		t.mu.Unlock()
		return io.EOF
	}
	t.wg.Add(1)
	t.mu.Unlock()

	pCopy := make([]byte, len(p))
	copy(pCopy, p)
	packetNum := t.packetCounter.Add(1)

	go func() {
		defer t.wg.Done()

		t.randLock.Lock()
		delay := t.latency
		if t.jitter > 0 {
			delay += time.Duration(t.r.Int63n(int64(t.jitter)))
		}
		shouldDrop := t.r.Float64() < t.lossRate
		shouldReorder := t.r.Float64() < t.reorderRate
		shouldDuplicate := t.r.Float64() < t.duplicateRate
		t.randLock.Unlock()

		time.Sleep(delay)

		if shouldDrop {
			return
		}

		isHandshake := packetNum <= 4

		t.reorderLock.Lock()
		if !isHandshake && shouldReorder {
			t.reorderBuffer = append(t.reorderBuffer, pCopy)
			if len(t.reorderBuffer) > 1 {
				pktToSend := t.reorderBuffer[0]
				t.reorderBuffer = t.reorderBuffer[1:]
				t.underlying.WritePacket(pktToSend)
			}
			t.reorderLock.Unlock()
			return
		}
		t.reorderLock.Unlock()

		t.underlying.WritePacket(pCopy)

		if !isHandshake && shouldDuplicate {
			time.Sleep(5 * time.Millisecond)
			t.underlying.WritePacket(pCopy)
		}
	}()
	return nil
}

func (t *adverseTransport) ReadPacket() ([]byte, error) {
	return t.underlying.ReadPacket()
}

func (t *adverseTransport) Close() error {
	t.mu.Lock()
	if t.isClosed {
		t.mu.Unlock()
		return nil
	}
	t.isClosed = true
	t.mu.Unlock()
	t.wg.Wait()
	t.reorderLock.Lock()
	defer t.reorderLock.Unlock()
	for _, p := range t.reorderBuffer {
		t.underlying.WritePacket(p)
	}
	t.reorderBuffer = nil
	return t.underlying.Close()
}

// pacedReader simulates a real-world data source by introducing a small delay.
type pacedReader struct {
	reader io.Reader
	delay  time.Duration
}

func (r *pacedReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err == nil {
		time.Sleep(r.delay)
	}
	return
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
	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan
	message := "Hello from the client! This is a test of the custom QUIC-like stack."
	var serverReceivedMessage string
	var transferWg sync.WaitGroup
	transferWg.Add(1)
	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		receivedBytes, err := io.ReadAll(stream)
		require.NoError(t, err)
		serverReceivedMessage = string(receivedBytes)
	}()
	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	_, err = stream.Write([]byte(message))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	transferWg.Wait()
	require.Equal(t, message, serverReceivedMessage)
	client.Close(nil)
	server.Close(nil)
	wg.Wait()
}

func TestBulkTransfer(t *testing.T) {
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
	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan
	const dataSize = 10 * 1024 * 1024 // 10 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)
	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	startTime := time.Now()

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err)
	}()
	go func() {
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		_, err = stream.Write(clientData)
		require.NoError(t, err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	underlyingTransport := newMockTransport()
	clientTransport := newAdverseTransport(underlyingTransport, 20*time.Millisecond, 10*time.Millisecond, 0.03, 0.02, 0.02)
	serverTransport := newAdverseTransport(underlyingTransport.Inverted(), 20*time.Millisecond, 10*time.Millisecond, 0.03, 0.02, 0.02)

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

	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan

	const dataSize = 5 * 1024 * 1024 // 5 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)

	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	startTime := time.Now()

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err)
	}()

	go func() {
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)

		clientDataReader := bytes.NewReader(clientData)
		pacedClientReader := &pacedReader{reader: clientDataReader, delay: 1 * time.Millisecond}
		buf := make([]byte, 8*1024)
		for {
			n, readErr := pacedClientReader.Read(buf)
			if n > 0 {
				dataToWrite := make([]byte, n)
				copy(dataToWrite, buf[:n])
				_, writeErr := stream.Write(dataToWrite)
				require.NoError(t, writeErr)
			}
			if readErr == io.EOF {
				break
			}
			require.NoError(t, readErr)
		}

		require.NoError(t, stream.Close())
	}()

	transferWg.Wait()

	duration := time.Since(startTime)
	mbps := (float64(len(serverReceivedData)) / (1024 * 1024)) / duration.Seconds()
	log.Printf("[SUCCESS] Unreliable bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v over an unreliable network.", len(serverReceivedData), duration)
	log.Printf("[STATS] Effective Speed: %.2f MB/s", mbps)

	client.Close(nil)
	server.Close(nil)
	wg.Wait()

	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData), "Data should be identical even over an unreliable link")
}

func TestHighPacketReordering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	underlying := newMockTransport()
	clientTransport := newAdverseTransport(underlying, 5*time.Millisecond, 0, 0, 0, 0.5)
	serverTransport := newAdverseTransport(underlying.Inverted(), 5*time.Millisecond, 0, 0, 0, 0.5)

	client, err := NewConnection(clientTransport, true)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); client.Run(ctx) }()
	go func() { defer wg.Done(); server.Run(ctx) }()

	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan

	var transferWg sync.WaitGroup
	transferWg.Add(1)
	const dataSize = 5 * 1024
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)
	var serverReceivedData []byte

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err)
	}()

	go func() {
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		_, err = stream.Write(clientData)
		require.NoError(t, err)
		err = stream.Close()
		require.NoError(t, err)
	}()

	transferWg.Wait()
	client.Close(nil)
	server.Close(nil)
	wg.Wait()

	require.True(t, bytes.Equal(clientData, serverReceivedData), "Data must be identical after reordering")
}

func TestPacketDuplication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	underlying := newMockTransport()
	clientTransport := newAdverseTransport(underlying, 5*time.Millisecond, 0, 0, 0.8, 0)
	serverTransport := newAdverseTransport(underlying.Inverted(), 5*time.Millisecond, 0, 0, 0.8, 0)

	client, err := NewConnection(clientTransport, true)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); client.Run(ctx) }()
	go func() { defer wg.Done(); server.Run(ctx) }()

	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan

	var transferWg sync.WaitGroup
	transferWg.Add(1)
	message := "This message should only be delivered once."
	clientData := []byte(message)
	var serverReceivedData []byte

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		serverReceivedData, err = io.ReadAll(stream)
		require.NoError(t, err)
	}()

	go func() {
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		_, err = stream.Write(clientData)
		require.NoError(t, err)
		err = stream.Close()
		require.NoError(t, err)
	}()

	transferWg.Wait()
	client.Close(nil)
	server.Close(nil)
	wg.Wait()

	require.Equal(t, message, string(serverReceivedData), "Data must be identical and not duplicated")
}

func TestExtremeLatencyVariation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	underlying := newMockTransport()
	clientTransport := newAdverseTransport(underlying, 5000*time.Millisecond, 100*time.Millisecond, 0, 0, 0)
	serverTransport := newAdverseTransport(underlying.Inverted(), 5000*time.Millisecond, 100*time.Millisecond, 0, 0, 0)

	client, err := NewConnection(clientTransport, true)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); client.Run(ctx) }()
	go func() { defer wg.Done(); server.Run(ctx) }()

	client.sendQueue <- &wire.PingFrame{}
	<-client.handshakeCompleteChan
	<-server.handshakeCompleteChan

	var transferWg sync.WaitGroup
	transferWg.Add(1)
	message := "Data over high-latency link"

	go func() {
		stream, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		_, err = io.Copy(stream, stream)
		require.True(t, err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled))
	}()

	go func() {
		defer transferWg.Done()
		stream, err := client.OpenStream(ctx)
		require.NoError(t, err)
		_, err = stream.Write([]byte(message))
		require.NoError(t, err)
		buf := make([]byte, len(message))
		_, err = io.ReadFull(stream, buf)
		require.NoError(t, err, "Failed to read echo from server")
		require.Equal(t, message, string(buf))
		stream.Close()
	}()

	transferWg.Wait()
	client.Close(nil)
	server.Close(nil)
	wg.Wait()
}
