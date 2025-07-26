package quicbuffer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dozyio/quic-buffer-go/logging"
	"github.com/stretchr/testify/require"
)

// mockTransport is a simple in-memory transport for testing.
type mockTransport struct {
	clientToServer chan []byte
	serverToClient chan []byte
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
		if packetNum <= 4 {
			t.underlying.WritePacket(pCopy)
			return
		}

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

		t.reorderLock.Lock()
		if shouldReorder {
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

		if shouldDuplicate {
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

// udpTransport is a transport layer that uses a real UDP socket.
type udpTransport struct {
	conn       *net.UDPConn
	remoteAddr net.Addr
	mu         sync.Mutex
}

func newUDPTransport(t testing.TB) *udpTransport {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	err = conn.SetReadBuffer(2 * 1024 * 1024)
	require.NoError(t, err)
	return &udpTransport{conn: conn}
}

func (t *udpTransport) WritePacket(p []byte) error {
	t.mu.Lock()
	remote := t.remoteAddr
	t.mu.Unlock()
	if remote == nil {
		return errors.New("udp transport: remote address not set")
	}
	_, err := t.conn.WriteTo(p, remote)
	return err
}

func (t *udpTransport) ReadPacket() ([]byte, error) {
	buf := make([]byte, 2048)
	n, remote, err := t.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	if t.remoteAddr == nil {
		t.remoteAddr = remote
	}
	t.mu.Unlock()
	return buf[:n], nil
}

func (t *udpTransport) Close() error {
	return t.conn.Close()
}

func (t *udpTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *udpTransport) SetRemoteAddr(addr net.Addr) {
	t.mu.Lock()
	t.remoteAddr = addr
	t.mu.Unlock()
}

var tcpBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 4+2048)
	},
}

type tcpTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPTransport(conn net.Conn) LowerLayerTransport {
	return &tcpTransport{conn: conn}
}

func (t *tcpTransport) WritePacket(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	buf := tcpBufferPool.Get().([]byte)
	defer tcpBufferPool.Put(buf)
	binary.BigEndian.PutUint32(buf, uint32(len(p)))
	copy(buf[4:], p)
	_, err := t.conn.Write(buf[:4+len(p)])
	return err
}

func (t *tcpTransport) ReadPacket() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	packetBuf := make([]byte, length)
	if _, err := io.ReadFull(t.conn, packetBuf); err != nil {
		return nil, err
	}
	return packetBuf, nil
}

func (t *tcpTransport) Close() error {
	return t.conn.Close()
}

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

func runConnection(ctx context.Context, conn *Connection) error {
	err := conn.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func TestTextMessageTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := newMockTransport()

	clientTracer := &logging.ConnectionTracer{
		// Log both long and short header packets.
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.Logf("<- [CLIENT] Received Long Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.Logf("<- [CLIENT] Received Short Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.Logf("-> [CLIENT] Sent Long Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.Logf("-> [CLIENT] Sent Short Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
	}

	// Create a tracer for the server.
	serverTracer := &logging.ConnectionTracer{
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.Logf("<- [SERVER] Received Long Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.Logf("<- [SERVER] Received Short Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.Logf("-> [SERVER] Sent Long Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.Logf("-> [SERVER] Sent Short Header Packet | PN: %d, Size: %d", hdr.PacketNumber, size)
		},
	}

	client, err := NewConnection(transport, true, clientTracer)
	require.NoError(t, err)
	server, err := NewConnection(transport.Inverted(), false, serverTracer)
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)

	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, client)
	}()
	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, server)
	}()

	message := "Hello from the client! This is a test of the custom QUIC-like stack."
	var serverReceivedMessage string
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		receivedBytes, err := io.ReadAll(stream)
		if err != nil {
			errChan <- err
			return
		}
		serverReceivedMessage = string(receivedBytes)
	}()

	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	_, err = stream.Write([]byte(message))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	transferWg.Wait()

	client.Close(nil)
	server.Close(nil)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
	require.Equal(t, message, serverReceivedMessage)
}

func TestBulkTransferOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport := newMockTransport()
	client, err := NewConnection(transport, true, nil)
	require.NoError(t, err)
	server, err := NewConnection(transport.Inverted(), false, nil)
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)

	go func() {
		defer wg.Done()
		err := runConnection(ctx, client)
		if err != nil {
			log.Printf("[CLIENT] runConnection error: %v", err)
		}
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		err := runConnection(ctx, server)
		if err != nil {
			log.Printf("[SERVER] runConnection error: %v", err)
		}
		errChan <- err
	}()

	const dataSize = 1024 * 1024 // 10 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)
	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(1)

	startTime := time.Now()

	go func() {
		defer transferWg.Done()
		log.Printf("[SERVER] Waiting to accept stream...")
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			log.Printf("[SERVER] AcceptStream error: %v", err)
			errChan <- err
			return
		}
		log.Printf("[SERVER] Accepted stream")
		serverReceivedData, err = io.ReadAll(stream)
		if err != nil {
			log.Printf("[SERVER] ReadAll error: %v", err)
			errChan <- err
			return
		}
		log.Printf("[SERVER] ReadAll complete, received %d bytes", len(serverReceivedData))
	}()

	log.Printf("[CLIENT] Opening stream...")
	stream, err := client.OpenStream(ctx)
	if err != nil {
		log.Printf("[CLIENT] OpenStream error: %v", err)
	}
	require.NoError(t, err)
	log.Printf("[CLIENT] Writing %d bytes to stream...", len(clientData))
	_, err = stream.Write(clientData)
	if err != nil {
		log.Printf("[CLIENT] Write error: %v", err)
	}
	require.NoError(t, err)
	log.Printf("[CLIENT] Closing stream...")
	err = stream.Close()
	if err != nil {
		log.Printf("[CLIENT] Close error: %v", err)
	}
	require.NoError(t, err)

	transferWg.Wait()
	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()
	log.Printf("[SUCCESS] Bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v.", dataSize, duration)
	log.Printf("[STATS] Speed: %.2f MB/s", mbps)

	log.Printf("[CLIENT] Closing connection...")
	client.Close(nil)
	log.Printf("[SERVER] Closing connection...")
	server.Close(nil)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			log.Printf("[ERROR] %v", err)
		}
		require.NoError(t, err)
	}
	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData))
}

func TestUnreliableBulkTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	underlyingTransport := newMockTransport()
	clientTransport := newAdverseTransport(underlyingTransport, 20*time.Millisecond, 10*time.Millisecond, 0.03, 0.02, 0.02)
	serverTransport := newAdverseTransport(underlyingTransport.Inverted(), 20*time.Millisecond, 10*time.Millisecond, 0.03, 0.02, 0.02)

	client, err := NewConnection(clientTransport, true, nil)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 4)

	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, client)
	}()
	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, server)
	}()

	const dataSize = 5 * 1024 * 1024 // 5 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)

	var serverReceivedData []byte
	var transferWg sync.WaitGroup
	transferWg.Add(2)

	startTime := time.Now()

	go func() {
		defer transferWg.Done()
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		serverReceivedData, err = io.ReadAll(stream)
		if err != nil {
			errChan <- err
		}
	}()

	go func() {
		defer transferWg.Done()
		stream, err := client.OpenStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		clientDataReader := bytes.NewReader(clientData)
		pacedClientReader := &pacedReader{reader: clientDataReader, delay: 1 * time.Millisecond}
		buf := make([]byte, 8*1024)
		for {
			n, readErr := pacedClientReader.Read(buf)
			if n > 0 {
				dataToWrite := make([]byte, n)
				copy(dataToWrite, buf[:n])
				if _, writeErr := stream.Write(dataToWrite); writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				errChan <- readErr
				return
			}
		}
		if err := stream.Close(); err != nil {
			errChan <- err
		}
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
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData), "Data should be identical even over an unreliable link")
}

func TestDuplexTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	transport := newMockTransport()
	client, err := NewConnection(transport, true, nil)
	require.NoError(t, err)
	server, err := NewConnection(transport.Inverted(), false, nil)
	require.NoError(t, err)

	var connWg sync.WaitGroup
	connWg.Add(2)
	errChan := make(chan error, 4)

	go func() {
		defer connWg.Done()
		errChan <- runConnection(ctx, client)
	}()
	go func() {
		defer connWg.Done()
		errChan <- runConnection(ctx, server)
	}()

	const dataSize = 10 * 1024 * 1024 // 10 MB
	var transferWg sync.WaitGroup
	transferWg.Add(2)

	// --- Transfer 1: Client to Server ---
	go func() {
		defer transferWg.Done()
		clientData := make([]byte, dataSize)
		if _, err := rand.Read(clientData); err != nil {
			errChan <- err
			return
		}
		var receivedData []byte
		var serverWg sync.WaitGroup
		serverWg.Add(1)

		go func() {
			defer serverWg.Done()
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				errChan <- err
				return
			}
			receivedData, err = io.ReadAll(stream)
			if err != nil {
				errChan <- err
			}
		}()

		stream, err := client.OpenStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		if _, err := stream.Write(clientData); err != nil {
			errChan <- err
			return
		}
		if err := stream.Close(); err != nil {
			errChan <- err
			return
		}
		serverWg.Wait()
		if !bytes.Equal(clientData, receivedData) {
			errChan <- errors.New("client-to-server data mismatch")
		}
	}()

	// --- Transfer 2: Server to Client ---
	go func() {
		defer transferWg.Done()
		serverData := make([]byte, dataSize)
		if _, err := rand.Read(serverData); err != nil {
			errChan <- err
			return
		}
		var receivedData []byte
		var clientWg sync.WaitGroup
		clientWg.Add(1)

		go func() {
			defer clientWg.Done()
			stream, err := client.AcceptStream(ctx)
			if err != nil {
				errChan <- err
				return
			}
			receivedData, err = io.ReadAll(stream)
			if err != nil {
				errChan <- err
			}
		}()

		stream, err := server.OpenStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		if _, err := stream.Write(serverData); err != nil {
			errChan <- err
			return
		}
		if err := stream.Close(); err != nil {
			errChan <- err
			return
		}
		clientWg.Wait()
		if !bytes.Equal(serverData, receivedData) {
			errChan <- errors.New("server-to-client data mismatch")
		}
	}()

	transferWg.Wait()
	log.Printf("[SUCCESS] Duplex transfer confirmed.")
	client.Close(nil)
	server.Close(nil)
	connWg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
}

func TestKeepAlive(t *testing.T) {
	keepAliveInterval := 1 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), keepAliveInterval*4)
	defer cancel()

	transport := newMockTransport()
	client, err := NewConnection(transport, true, nil)
	require.NoError(t, err)
	client.keepAliveInterval = keepAliveInterval
	server, err := NewConnection(transport.Inverted(), false, nil)
	require.NoError(t, err)
	server.keepAliveInterval = keepAliveInterval

	var connWg sync.WaitGroup
	connWg.Add(2)
	errChan := make(chan error, 2)

	go func() {
		defer connWg.Done()
		errChan <- runConnection(ctx, client)
	}()
	go func() {
		defer connWg.Done()
		errChan <- runConnection(ctx, server)
	}()

	// Open a stream to ensure handshake is complete
	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	stream.Close()

	log.Printf("[TEST] Handshake complete. Idling to trigger keep-alive after %v...", keepAliveInterval)
	time.Sleep(keepAliveInterval + keepAliveInterval/2)

	// Verify the connection is still alive by opening a new stream.
	_, err = client.OpenStream(ctx)
	require.NoError(t, err, "Failed to open new stream; connection appears to be closed.")
	log.Printf("[SUCCESS] Connection is still alive after keep-alive interval.")

	client.Close(nil)
	server.Close(nil)
	connWg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
}

func TestIdleTimeoutWithNetworkFailure(t *testing.T) {
	idleTimeout := 3 * time.Second
	keepAliveInterval := 1 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), idleTimeout*2)
	defer cancel()

	underlying := newMockTransport()
	clientTransport := underlying
	serverTransport := newAdverseTransport(underlying.Inverted(), 0, 0, 1.0, 0, 0)

	client, err := NewConnection(clientTransport, true, nil)
	require.NoError(t, err)
	client.idleTimeout = idleTimeout
	client.keepAliveInterval = keepAliveInterval

	server, err := NewConnection(serverTransport, false, nil)
	require.NoError(t, err)
	server.idleTimeout = idleTimeout
	server.keepAliveInterval = keepAliveInterval

	var wg sync.WaitGroup
	wg.Add(2)
	clientErrChan := make(chan error, 1)

	go func() {
		defer wg.Done()
		clientErrChan <- runConnection(ctx, client)
	}()
	go func() {
		defer wg.Done()
		runConnection(ctx, server)
	}()

	// Open a stream to complete the handshake.
	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	stream.Close() // Close it immediately, we just needed it for the handshake.

	log.Printf("[TEST] Handshake complete. Simulating network failure. Client should time out after ~%v", idleTimeout)

	var clientErr error
	select {
	case clientErr = <-clientErrChan:
		log.Printf("[TEST] Client returned with error: %v", clientErr)
	case <-ctx.Done():
		t.Fatal("Test timed out before client could return an error.")
	}
	cancel()
	wg.Wait()

	require.Error(t, clientErr, "Client should have returned an error")
	require.Contains(t, clientErr.Error(), "idle timeout", "Client error should be due to idle timeout")
	log.Printf("[SUCCESS] Client correctly closed connection due to idle timeout.")
}

func TestBulkTransferUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverTransport := newUDPTransport(t)
	clientTransport := newUDPTransport(t)
	clientTransport.SetRemoteAddr(serverTransport.LocalAddr())

	client, err := NewConnection(clientTransport, true, nil)
	require.NoError(t, err)
	server, err := NewConnection(serverTransport, false, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)

	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, client)
	}()
	go func() {
		defer wg.Done()
		errChan <- runConnection(ctx, server)
	}()

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
		if err != nil {
			errChan <- err
			return
		}
		serverReceivedData, err = io.ReadAll(stream)
		if err != nil {
			errChan <- err
		}
	}()

	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	_, err = stream.Write(clientData)
	require.NoError(t, err)
	require.NoError(t, stream.Close())

	transferWg.Wait()
	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()
	log.Printf("[SUCCESS] UDP Bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v.", dataSize, duration)
	log.Printf("[STATS] Speed: %.2f MB/s", mbps)

	client.Close(nil)
	server.Close(nil)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData))
}

func TestBulkTransferOverTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	const dataSize = 10 * 1024 * 1024 // 10 MB
	clientData := make([]byte, dataSize)
	_, err = rand.Read(clientData)
	require.NoError(t, err)

	var serverReceivedData []byte
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpConn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				errChan <- err
			}
			return
		}
		serverTransport := newTCPTransport(tcpConn)
		server, err := NewConnection(serverTransport, false, nil)
		if err != nil {
			errChan <- err
			return
		}
		go func() {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				errChan <- err
				return
			}
			serverReceivedData, err = io.ReadAll(stream)
			if err != nil {
				errChan <- err
			}
		}()
		errChan <- runConnection(ctx, server)
	}()

	tcpConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	clientTransport := newTCPTransport(tcpConn)
	client, err := NewConnection(clientTransport, true, nil)
	require.NoError(t, err)
	go runConnection(ctx, client)

	startTime := time.Now()
	stream, err := client.OpenStream(ctx)
	require.NoError(t, err)
	_, err = stream.Write(clientData)
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)

	wg.Wait()
	duration := time.Since(startTime)
	mbps := (float64(dataSize) / (1024 * 1024)) / duration.Seconds()
	log.Printf("[SUCCESS] QUIC-over-TCP Bulk transfer confirmed.")
	log.Printf("[STATS] Transferred %d bytes in %v.", dataSize, duration)
	log.Printf("[STATS] QUIC-over-TCP Speed: %.2f MB/s", mbps)

	client.Close(nil)
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
	require.Equal(t, len(clientData), len(serverReceivedData))
	require.True(t, bytes.Equal(clientData, serverReceivedData))
}
