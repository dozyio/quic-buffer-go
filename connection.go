package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/dozyio/quic-buffer-go/internal/ackhandler"
	"github.com/dozyio/quic-buffer-go/internal/congestion"
	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/handshake"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/utils"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

// retransmissionHandler implements the ackhandler.FrameHandler interface.
type retransmissionHandler struct {
	conn *Connection
}

func (h *retransmissionHandler) OnAcked(f wire.Frame) {}

func (h *retransmissionHandler) OnLost(f wire.Frame) {
	log.Printf("[RETRANS] Re-queuing lost frame of type %T", f)
	h.conn.retransmissionQueue.Add(f)
}

// dummyLogger is a no-op logger to satisfy quic-go's internal interfaces.
type dummyLogger struct{}

func (l *dummyLogger) DropPacket(ptype protocol.PacketType, pn protocol.PacketNumber, reason string) {
}
func (l *dummyLogger) Debugf(format string, args ...any)     {}
func (l *dummyLogger) Infof(format string, args ...any)      {}
func (l *dummyLogger) Errorf(format string, args ...any)     {}
func (l *dummyLogger) WithPrefix(prefix string) utils.Logger { return l }
func (l *dummyLogger) Debug() bool                           { return false }
func (l *dummyLogger) SetLogLevel(level utils.LogLevel)      {}
func (l *dummyLogger) SetLogTimeFormat(format string)        {}

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
	ackMu                 sync.Mutex // Protects ack handlers and handshake state
	congestionController  congestion.SendAlgorithmWithDebugInfos
	connFlowController    flowcontrol.ConnectionFlowController
	rttStats              *utils.RTTStats

	// Dummy crypto
	longHeaderSealer  handshake.LongHeaderSealer
	longHeaderOpener  handshake.LongHeaderOpener
	shortHeaderSealer handshake.ShortHeaderSealer
	shortHeaderOpener handshake.ShortHeaderOpener

	// Data to send
	sendQueue           chan wire.Frame
	retransmissionQueue *retransmissionQueue
	closeChan           chan struct{}
	logger              utils.Logger

	handshakeComplete     bool
	handshakeCompleteChan chan struct{}
}

// NewConnection creates and initializes a new connection.
func NewConnection(transport LowerLayerTransport, isClient bool) (*Connection, error) {
	connID, _ := protocol.GenerateConnectionID(8)
	logger := &dummyLogger{}
	rttStats := &utils.RTTStats{}

	perspective := protocol.PerspectiveClient
	if !isClient {
		perspective = protocol.PerspectiveServer
	}

	c := &Connection{
		transport:             transport,
		isClient:              isClient,
		destConnID:            connID,
		streams:               make(map[protocol.StreamID]*Stream),
		acceptQueue:           make(chan *Stream, 10),
		rttStats:              rttStats,
		longHeaderSealer:      &nullLongHeaderAEAD{},
		longHeaderOpener:      &nullLongHeaderAEAD{},
		shortHeaderSealer:     &nullShortHeaderAEAD{},
		shortHeaderOpener:     &nullShortHeaderAEAD{},
		sendQueue:             make(chan wire.Frame, 10000),
		closeChan:             make(chan struct{}),
		logger:                logger,
		handshakeCompleteChan: make(chan struct{}),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.retransmissionQueue = newRetransmissionQueue(c)

	c.congestionController = congestion.NewCubicSender(
		congestion.DefaultClock{},
		c.rttStats,
		protocol.InitialPacketSize,
		true, // Use Reno
		nil,
	)

	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		func(protocol.ByteCount) bool { return true }, // No-op window update function
		c.rttStats,
		c.logger,
	)

	if isClient {
		c.nextStreamID = 0
	} else {
		c.nextStreamID = 1
	}

	sentPacketHandler, receivedPacketHandler := ackhandler.NewAckHandler(
		0,
		protocol.InitialPacketSize,
		c.rttStats,
		!isClient,
		false,
		perspective,
		nil,
		c.logger,
	)
	c.sentPacketHandler = sentPacketHandler
	c.receivedPacketHandler = receivedPacketHandler

	return c, nil
}

// Run starts the connection's main send and receive loops. It blocks until the context is done.
func (c *Connection) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		err := c.receiveLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			errChan <- err
		}
	}()
	go func() {
		defer wg.Done()
		err := c.sendLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
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
		return nil
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

		const ackEliciting = true
		var encLevel protocol.EncryptionLevel

		if wire.IsLongHeaderPacket(data[0]) {
			hdr, packetData, _, err := wire.ParsePacket(data)
			if err != nil {
				log.Printf("[RECV] Failed to parse long header packet: %v", err)
				continue
			}
			extHdr, err := hdr.ParseExtended(data)
			if err != nil {
				log.Printf("[RECV] Failed to parse extended header: %v", err)
				continue
			}
			payload, err := c.longHeaderOpener.Open(nil, packetData[extHdr.ParsedLen():], extHdr.PacketNumber, packetData[:extHdr.ParsedLen()])
			if err != nil {
				log.Printf("[RECV] Failed to 'decrypt' long header packet: %v", err)
				continue
			}
			encLevel = protocol.EncryptionInitial
			c.ackMu.Lock()
			c.receivedPacketHandler.ReceivedPacket(extHdr.PacketNumber, protocol.ECNUnsupported, encLevel, time.Now(), ackEliciting)
			c.ackMu.Unlock()
			c.handleFrames(payload, encLevel)
		} else {
			c.ackMu.Lock()
			if c.isClient && !c.handshakeComplete {
				c.handshakeComplete = true
				close(c.handshakeCompleteChan)
			}
			c.ackMu.Unlock()

			_, pn, pnLen, kp, err := wire.ParseShortHeader(data, c.destConnID.Len())
			if err != nil {
				log.Printf("[RECV] Failed to parse short header: %v", err)
				continue
			}
			hdrLen := 1 + c.destConnID.Len() + int(pnLen)
			payload, err := c.shortHeaderOpener.Open(nil, data[hdrLen:], time.Now(), pn, kp, data[:hdrLen])
			if err != nil {
				log.Printf("[RECV] Failed to 'decrypt' short header packet: %v", err)
				continue
			}
			encLevel = protocol.Encryption1RTT
			c.ackMu.Lock()
			c.receivedPacketHandler.ReceivedPacket(pn, protocol.ECNUnsupported, encLevel, time.Now(), ackEliciting)
			c.ackMu.Unlock()
			c.handleFrames(payload, encLevel)
		}
	}
}

func (c *Connection) handleFrames(payload []byte, encLevel protocol.EncryptionLevel) {
	frameParser := wire.NewFrameParser(true, true)
	frameData := payload
	for len(frameData) > 0 {
		bytesRead, frame, err := frameParser.ParseNext(frameData, encLevel, protocol.Version1)
		if err != nil {
			log.Printf("[RECV] Failed to parse frame: %v", err)
			break
		}
		if frame == nil {
			break
		}
		c.handleFrame(frame, encLevel)
		frameData = frameData[bytesRead:]
	}
}

func (c *Connection) handleFrame(frame wire.Frame, encLevel protocol.EncryptionLevel) {
	switch f := frame.(type) {
	case *wire.StreamFrame:
		c.streamsMu.RLock()
		stream, ok := c.streams[f.StreamID]
		c.streamsMu.RUnlock()

		if !ok {
			stream = c.newStream(f.StreamID)
			c.streamsMu.Lock()
			c.streams[f.StreamID] = stream
			c.streamsMu.Unlock()
			stream.handleStreamFrame(f)
			select {
			case c.acceptQueue <- stream:
			default:
				log.Printf("Accept queue full, dropping stream %d", f.StreamID)
			}
		} else {
			stream.handleStreamFrame(f)
		}

	case *wire.AckFrame:
		c.ackMu.Lock()
		log.Printf("[RECV] Got ACK frame for %s level, acknowledging ranges: %v", encLevel, f.AckRanges)
		if _, err := c.sentPacketHandler.ReceivedAck(f, encLevel, time.Now()); err != nil {
			log.Printf("Error processing ACK frame: %v", err)
		}
		c.ackMu.Unlock()

	case *wire.PingFrame:
		c.ackMu.Lock()
		log.Printf("[RECV] Got PING frame.")
		if !c.isClient && !c.handshakeComplete {
			c.handshakeComplete = true
			close(c.handshakeCompleteChan)
		}
		c.ackMu.Unlock()

	default:
		log.Printf("[RECV] Ignoring frame of type %T", f)
	}
}

// sendLoop is the main event loop for sending packets.
func (c *Connection) sendLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if err := c.sendPackets(); err != nil {
			return err
		}
	}
}

func (c *Connection) sendPackets() error {
	c.ackMu.Lock()
	if err := c.sentPacketHandler.OnLossDetectionTimeout(time.Now()); err != nil {
		log.Printf("Loss detection error: %v", err)
	}
	c.ackMu.Unlock()

	var frames []wire.Frame

	// Priority 1: ACKs
	c.ackMu.Lock()
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, time.Now(), false); ack != nil {
		frames = append(frames, ack)
	}
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now(), false); ack != nil {
		frames = append(frames, ack)
	}
	c.ackMu.Unlock()

	// Priority 2: Retransmissions
	for c.retransmissionQueue.HasData() {
		frames = append(frames, c.retransmissionQueue.GetFrame())
	}

	// Priority 3: New Data
DrainNewData:
	for {
		select {
		case frame := <-c.sendQueue:
			frames = append(frames, frame)
		default:
			break DrainNewData
		}
	}

	if len(frames) == 0 {
		return nil
	}

	for len(frames) > 0 {
		var err error
		frames, err = c.packAndSendPacket(frames)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Connection) packAndSendPacket(frames []wire.Frame) (remainingFrames []wire.Frame, err error) {
	var pn protocol.PacketNumber
	var pnLen protocol.PacketNumberLen
	var encLevel protocol.EncryptionLevel

	c.ackMu.Lock()
	isHandshakeComplete := c.handshakeComplete
	c.ackMu.Unlock()

	if !isHandshakeComplete {
		encLevel = protocol.EncryptionInitial
	} else {
		encLevel = protocol.Encryption1RTT
	}

	c.ackMu.Lock()
	pn, pnLen = c.sentPacketHandler.PeekPacketNumber(encLevel)
	c.sentPacketHandler.PopPacketNumber(encLevel)
	c.ackMu.Unlock()

	var payloadLength int
	var framesInPacket []wire.Frame
	var ackFramesInPacket []ackhandler.Frame
	var cutoff int

	maxPacketSize := protocol.InitialPacketSize - 40
	handler := c.retransmissionQueue.FrameHandler(encLevel)

	for i, frame := range frames {
		if _, isStream := frame.(*wire.StreamFrame); isStream && encLevel == protocol.EncryptionInitial {
			continue
		}
		frameLen := int(frame.Length(protocol.Version1))
		if payloadLength+frameLen > maxPacketSize && payloadLength > 0 {
			break
		}

		payloadLength += frameLen
		framesInPacket = append(framesInPacket, frame)
		ackFramesInPacket = append(ackFramesInPacket, ackhandler.Frame{
			Frame:   frame,
			Handler: handler,
		})
		cutoff = i + 1
	}

	if len(framesInPacket) == 0 {
		if cutoff < len(frames) {
			return frames[cutoff:], nil
		}
		return nil, nil
	}

	payloadBuf := getPacketBuffer()
	defer putPacketBuffer(payloadBuf)
	for _, frame := range framesInPacket {
		b, err := frame.Append(payloadBuf.Bytes(), protocol.Version1)
		if err != nil {
			return nil, err
		}
		payloadBuf.Reset()
		payloadBuf.Write(b)
	}

	var raw []byte
	var overhead int
	var sealer handshake.LongHeaderSealer

	if encLevel == protocol.EncryptionInitial {
		sealer = c.longHeaderSealer
		overhead = sealer.Overhead()
		hdr := &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: c.destConnID,
				SrcConnectionID:  c.destConnID,
				Length:           protocol.ByteCount(payloadBuf.Len() + int(pnLen) + overhead),
				Version:          protocol.Version1,
			},
			PacketNumber:    pn,
			PacketNumberLen: pnLen,
		}
		raw, err = hdr.Append(nil, protocol.Version1)
	} else {
		sealer = c.shortHeaderSealer
		raw, err = wire.AppendShortHeader(nil, c.destConnID, pn, pnLen, c.shortHeaderSealer.KeyPhase())
	}
	if err != nil {
		return nil, err
	}

	c.ackMu.Lock()
	var streamFrames []ackhandler.StreamFrame
	c.sentPacketHandler.SentPacket(
		time.Now(), pn, protocol.InvalidPacketNumber, streamFrames, ackFramesInPacket,
		encLevel, protocol.ECNUnsupported, protocol.ByteCount(payloadBuf.Len()+len(raw)+overhead),
		true,
		false,
	)
	c.ackMu.Unlock()

	payload := sealer.Seal(nil, payloadBuf.Bytes(), pn, raw)
	raw = append(raw, payload...)

	log.Printf("[SEND] Sending packet %d with %d frames.", pn, len(framesInPacket))
	err = c.transport.WritePacket(raw)
	if err != nil {
		return nil, err
	}

	if cutoff < len(frames) {
		return frames[cutoff:], nil
	}
	return nil, nil
}

// OpenStream creates a new stream for the application to use.
func (c *Connection) OpenStream(ctx context.Context) (*Stream, error) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	streamID := c.nextStreamID
	c.nextStreamID += 2

	stream := c.newStream(streamID)
	c.streams[streamID] = stream
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
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		protocol.ByteCount(protocol.DefaultInitialMaxStreamData),
		c.rttStats,
		c.logger,
	)

	stream := newStream(c.ctx, id, c, fc)
	return stream
}

// sendStreamData is called by a Stream to queue its data for sending.
func (c *Connection) sendStreamData(id protocol.StreamID, data []byte, fin bool, offset protocol.ByteCount) {
	frame := &wire.StreamFrame{
		StreamID:       id,
		Offset:         offset,
		Data:           data,
		Fin:            fin,
		DataLenPresent: true,
	}
	c.sendQueue <- frame
}

// Close shuts down the connection.
func (c *Connection) Close(err error) {
	c.cancel()
	c.transport.Close()
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	for _, s := range c.streams {
		s.cancelRead(err)
	}
}

var packetBufferPool = sync.Pool{
	New: func() any {
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
