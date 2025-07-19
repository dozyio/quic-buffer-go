package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/dozyio/quic-buffer-go/ackhandler"
	"github.com/dozyio/quic-buffer-go/congestion"
	"github.com/dozyio/quic-buffer-go/flowcontrol"
	"github.com/dozyio/quic-buffer-go/handshake"
	"github.com/dozyio/quic-buffer-go/protocol"
	"github.com/dozyio/quic-buffer-go/utils"
	"github.com/dozyio/quic-buffer-go/wire"
)

// dummyLogger is a no-op logger to satisfy quic-go's internal interfaces.
type dummyLogger struct{}

func (l *dummyLogger) DropPacket(ptype protocol.PacketType, pn protocol.PacketNumber, reason string) {
}
func (l *dummyLogger) Debugf(format string, args ...interface{}) {}
func (l *dummyLogger) Infof(format string, args ...interface{})  {}
func (l *dummyLogger) Errorf(format string, args ...interface{}) {}
func (l *dummyLogger) WithPrefix(prefix string) utils.Logger     { return l }

// Connection is the central object that manages the entire QUIC-like session.
type Connection struct {
	transport LowerLayerTransport
	isClient  bool
	ctx       context.Context
	cancel    context.CancelFunc

	// State
	destConnID       protocol.ConnectionID
	nextPacketNumber protocol.PacketNumber
	nextStreamID     protocol.StreamID
	streams          map[protocol.StreamID]*Stream
	streamsMu        sync.RWMutex
	acceptQueue      chan *Stream // For AcceptStream()

	// quic-go components
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	congestionController  congestion.CongestionController
	connFlowController    flowcontrol.ConnectionFlowController
	rttStats              *congestion.RTTStats

	// Dummy crypto
	sealer handshake.Sealer
	opener handshake.Opener

	// Data to send
	sendQueue chan wire.Frame
	closeChan chan struct{}
	logger    utils.Logger
}

// NewConnection creates and initializes a new connection.
func NewConnection(transport LowerLayerTransport, isClient bool) (*Connection, error) {
	connID, _ := protocol.GenerateConnectionID(8)
	logger := &dummyLogger{}

	c := &Connection{
		transport:   transport,
		isClient:    isClient,
		destConnID:  connID,
		streams:     make(map[protocol.StreamID]*Stream),
		acceptQueue: make(chan *Stream, 10),
		rttStats:    congestion.NewRTTStats(),
		sealer:      &nullAEAD{},
		opener:      &nullAEAD{},
		sendQueue:   make(chan wire.Frame, 100),
		closeChan:   make(chan struct{}),
		logger:      logger,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.congestionController = congestion.NewCubicSender(
		congestion.DefaultClock{},
		c.rttStats,
		protocol.InitialCongestionWindow, // Initial window
		true,                             // Use Reno
		c.logger,
	)

	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.InitialMaxData,
		protocol.InitialMaxData,
		func(protocol.ByteCount) {}, // No-op window update function
		c.rttStats,
		c.logger,
	)

	if isClient {
		c.nextStreamID = 0
	} else {
		c.nextStreamID = 1
	}

	c.sentPacketHandler = ackhandler.NewSentPacketHandler(
		c.rttStats,
		c.congestionController,
		c.logger,
	)

	c.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(
		c.rttStats,
		c.logger,
	)

	return c, nil
}

// Run starts the connection's main send and receive loops. It blocks until the context is done.
func (c *Connection) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := c.receiveLoop(ctx); err != nil && err != context.Canceled && !errors.Is(err, io.EOF) {
			errChan <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := c.sendLoop(ctx); err != nil && err != context.Canceled {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		c.Close(err)
		return err
	case <-ctx.Done():
		c.Close(ctx.Err())
		wg.Wait()
		return ctx.Err()
	case <-c.ctx.Done():
		wg.Wait()
		return c.ctx.Err()
	}
}

// receiveLoop continuously reads from the transport and processes incoming packets.
func (c *Connection) receiveLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := c.transport.ReadPacket()
		if err != nil {
			return err
		}

		hdr, packetData, _, err := wire.ParsePacket(data)
		if err != nil {
			log.Printf("[RECV] Failed to parse packet header: %v", err)
			continue
		}

		hdr.PacketNumber, hdr.PacketNumberLen, err = wire.DecodePacketNumber(
			hdr.PacketNumberLen,
			c.nextPacketNumber,
			hdr.Raw[len(hdr.Raw)-int(hdr.PacketNumberLen):],
		)
		if err != nil {
			log.Printf("[RECV] Failed to decode packet number: %v", err)
			continue
		}

		payload, err := c.opener.Open(nil, packetData, hdr.PacketNumber, hdr.Raw)
		if err != nil {
			log.Printf("[RECV] Failed to 'decrypt' packet: %v", err)
			continue
		}

		// Let the ackhandler know we received this packet.
		c.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, protocol.ECNUnsupported, protocol.Encryption1RTT, time.Now(), true)

		// Parse frames.
		r := bytes.NewReader(payload)
		for r.Len() > 0 {
			frame, err := wire.ParseNextFrame(r, hdr.Type, protocol.Version1)
			if err != nil {
				log.Printf("[RECV] Failed to parse frame: %v", err)
				break
			}
			c.handleFrame(frame)
		}
	}
}

// handleFrame processes a single parsed frame.
func (c *Connection) handleFrame(frame wire.Frame) {
	switch f := frame.(type) {
	case *wire.StreamFrame:
		log.Printf("[RECV] Got STREAM frame for stream %d, len %d, fin: %t", f.StreamID, f.Len(), f.Fin)
		c.streamsMu.RLock()
		stream, ok := c.streams[f.StreamID]
		c.streamsMu.RUnlock()
		if !ok {
			stream = c.newStream(f.StreamID)
			select {
			case c.acceptQueue <- stream:
			default:
				log.Printf("Accept queue full, dropping stream %d", f.StreamID)
			}
		}
		stream.handleStreamFrame(f)

	case *wire.AckFrame:
		log.Printf("[RECV] Got ACK frame.")
		err := c.sentPacketHandler.ReceivedAck(f, protocol.Encryption1RTT, time.Now())
		if err != nil {
			log.Printf("Error processing ACK frame: %v", err)
		}

	default:
		log.Printf("[RECV] Ignoring frame of type %T", f)
	}
}

// sendLoop continuously bundles frames from the sendQueue into packets and sends them.
func (c *Connection) sendLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var frames []wire.Frame
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-c.sendQueue:
			frames = append(frames, frame)
		case <-ticker.C:
			if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now()); ack != nil {
				frames = append(frames, ack)
			}

			if len(frames) == 0 {
				continue
			}

			if err := c.sendPacket(frames); err != nil {
				return err
			}
			frames = nil
		}
	}
}

// sendPacket constructs and sends a single packet containing the given frames.
func (c *Connection) sendPacket(frames []wire.Frame) error {
	pn := c.nextPacketNumber
	c.nextPacketNumber++

	hdr := &wire.Header{
		Type:             protocol.PacketType1RTT,
		DestConnectionID: c.destConnID,
		PacketNumberLen:  protocol.PacketNumberLen4,
	}

	payloadBuf := getPacketBuffer()
	defer putPacketBuffer(payloadBuf)

	for _, frame := range frames {
		if err := frame.Write(payloadBuf, protocol.Version1); err != nil {
			return err
		}
	}

	// Let the ackhandler know what we're sending.
	c.sentPacketHandler.SentPacket(
		time.Now(),
		pn,
		protocol.InvalidPacketNumber,
		nil,
		nil,
		protocol.Encryption1RTT,
		protocol.ECNUnsupported,
		protocol.ByteCount(payloadBuf.Len()),
		true,
		false,
	)

	// "Encrypt" the payload
	encryptedPayload := c.sealer.Seal(nil, payloadBuf.Bytes(), pn, nil)

	// Compose the packet
	raw, err := wire.AppendShortHeader(nil, hdr, encryptedPayload)
	if err != nil {
		return err
	}

	log.Printf("[SEND] Sending packet %d with %d frames.", pn, len(frames))
	return c.transport.WritePacket(raw)
}

// OpenStream creates a new stream for the application to use.
func (c *Connection) OpenStream(ctx context.Context) (*Stream, error) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	streamID := c.nextStreamID
	c.nextStreamID += 2

	stream := c.newStream(streamID)
	return stream, nil
}

// AcceptStream waits for and returns the next stream initiated by the peer.
func (c *Connection) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case stream := <-c.acceptQueue:
		return stream, nil
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// newStream is an internal helper to create and register a new stream.
func (c *Connection) newStream(id protocol.StreamID) *Stream {
	fc := flowcontrol.NewStreamFlowController(
		id,
		c.connFlowController,
		protocol.InitialMaxStreamDataBidiLocal,
		protocol.InitialMaxStreamDataBidiLocal,
		protocol.ByteCount(protocol.InitialMaxStreamDataBidiLocal),
		c.rttStats,
		c.logger,
	)

	stream := newStream(c.ctx, id, c, fc)
	c.streams[id] = stream
	return stream
}

// sendStreamData is called by a Stream to queue its data for sending.
func (c *Connection) sendStreamData(id protocol.StreamID, data []byte, fin bool) {
	// A real implementation would manage stream offsets and chunk data.
	frame := &wire.StreamFrame{
		StreamID: id,
		Offset:   0,
		Data:     data,
		Fin:      fin,
	}
	frame.SetLen(uint64(len(data)))
	c.sendQueue <- frame
}

// Close shuts down the connection.
func (c *Connection) Close(err error) {
	c.cancel() // This cancels the connection's context
	c.transport.Close()
	// Cancel all active streams
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	for _, s := range c.streams {
		s.cancelRead(err)
	}
}

// Simple buffer pool for packet payloads
var packetBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func getPacketBuffer() *bytes.Buffer {
	return packetBufferPool.Get().(*bytes.Buffer)
}

func putPacketBuffer(buf *bytes.Buffer) {
	buf.Reset()
	packetBufferPool.Put(buf)
}
