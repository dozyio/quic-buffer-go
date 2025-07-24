package main

import (
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

// ... (retransmissionHandler and dummyLogger remain the same) ...
type retransmissionHandler struct {
	conn *Connection
}

func (h *retransmissionHandler) OnAcked(f wire.Frame) {}
func (h *retransmissionHandler) OnLost(f wire.Frame) {
	log.Printf("[%s][RETRANS] Re-queuing lost frame of type %T", h.conn.side(), f)
	h.conn.retransmissionQueue.Add(f)
}

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

// Connection now uses the sender interface and more granular locking.
type Connection struct {
	transport             oobCapablePacketConn
	isClient              bool
	ctx                   context.Context
	cancel                context.CancelFunc
	destConnID            protocol.ConnectionID
	nextStreamID          protocol.StreamID
	streams               map[protocol.StreamID]*Stream
	streamsMu             sync.RWMutex
	acceptQueue           chan *Stream
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	congestionController  congestion.SendAlgorithmWithDebugInfos
	connFlowController    flowcontrol.ConnectionFlowController
	rttStats              *utils.RTTStats
	longHeaderSealer      handshake.LongHeaderSealer
	longHeaderOpener      handshake.LongHeaderOpener
	shortHeaderSealer     handshake.ShortHeaderSealer
	shortHeaderOpener     handshake.ShortHeaderOpener
	retransmissionQueue   *retransmissionQueue
	logger                utils.Logger
	handshakeComplete     bool
	handshakeCompleteChan chan struct{}
	handshakeTimer        *time.Timer
	handshakeTimeout      time.Duration
	initialKeysDropped    bool
	sendingScheduled      chan struct{}
	initialPacketSent     bool

	// The new sender, replacing the old sendQueue channel
	sender sender

	// A single mutex to protect all ACK and handshake related state
	ackMu sync.Mutex

	// closeOnce ensures that the connection is only closed once.
	closeOnce sync.Once
	closed    chan struct{}
}

func NewConnection(transport LowerLayerTransport, isClient bool) (*Connection, error) {
	connID, _ := protocol.GenerateConnectionID(8)
	logger := &dummyLogger{}
	rttStats := &utils.RTTStats{}
	perspective := protocol.PerspectiveClient
	if !isClient {
		perspective = protocol.PerspectiveServer
	}

	oobTransport, ok := transport.(oobCapablePacketConn)
	if !ok {
		return nil, errors.New("transport does not support OOB")
	}

	c := &Connection{
		transport:             oobTransport,
		isClient:              isClient,
		destConnID:            connID,
		streams:               make(map[protocol.StreamID]*Stream),
		acceptQueue:           make(chan *Stream, 10),
		rttStats:              rttStats,
		longHeaderSealer:      &nullLongHeaderAEAD{},
		longHeaderOpener:      &nullLongHeaderAEAD{},
		shortHeaderSealer:     &nullShortHeaderAEAD{},
		shortHeaderOpener:     &nullShortHeaderAEAD{},
		logger:                logger,
		handshakeCompleteChan: make(chan struct{}),
		handshakeTimeout:      1 * time.Second,
		sendingScheduled:      make(chan struct{}, 1),
		closed:                make(chan struct{}),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.sender = newSendQueue(c.transport) // Initialize the new sender
	c.retransmissionQueue = newRetransmissionQueue(c)
	c.congestionController = congestion.NewCubicSender(congestion.DefaultClock{}, c.rttStats, protocol.InitialPacketSize, true, nil)
	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData, protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		func(protocol.ByteCount) bool { return true }, c.rttStats, c.logger,
	)
	if isClient {
		c.nextStreamID = 0
	} else {
		c.nextStreamID = 1
	}
	sentPacketHandler, receivedPacketHandler := ackhandler.NewAckHandler(0, protocol.InitialPacketSize, c.rttStats, !isClient, false, perspective, nil, c.logger)
	c.sentPacketHandler = sentPacketHandler
	c.receivedPacketHandler = receivedPacketHandler
	return c, nil
}

// Run now starts the sender and packer loops in addition to the receive loop.
func (c *Connection) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 3) // Increased to 3 for the new packer loop

	wg.Add(3)

	// 1. The receive loop (mostly unchanged)
	go func() {
		defer wg.Done()
		err := c.receiveLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			errChan <- err
		}
	}()

	// 2. The new packer loop, which feeds the sender
	go func() {
		defer wg.Done()
		err := c.packerLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			errChan <- err
		}
	}()

	// 3. The sender's own run loop
	go func() {
		defer wg.Done()
		err := c.sender.Run()
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

// receiveLoop is largely the same, but locking is more granular.
func (c *Connection) receiveLoop(ctx context.Context) error {
	frameParser := wire.NewFrameParser(false, true)
	for {
		// This check should be at the top of the loop to exit promptly.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := c.transport.ReadPacket()
		if err != nil {
			return err
		}
		var (
			payload                        []byte
			encLevel                       protocol.EncryptionLevel
			handshakeCompletedInThisPacket bool
		)
		if wire.IsLongHeaderPacket(data[0]) {
			c.ackMu.Lock()
			if c.initialKeysDropped {
				c.ackMu.Unlock()
				continue
			}
			c.ackMu.Unlock()

			hdr, packetData, _, err := wire.ParsePacket(data)
			if err != nil {
				continue
			}
			extHdr, err := hdr.ParseExtended(data)
			if err != nil {
				continue
			}
			payload, err = c.longHeaderOpener.Open(nil, packetData[extHdr.ParsedLen():], extHdr.PacketNumber, packetData[:extHdr.ParsedLen()])
			if err != nil {
				continue
			}
			encLevel = protocol.EncryptionInitial
			c.ackMu.Lock()
			if c.isClient && !c.handshakeComplete {
				handshakeCompletedInThisPacket = true
				c.handshakeComplete = true
				if c.handshakeTimer != nil {
					c.handshakeTimer.Stop()
				}
				close(c.handshakeCompleteChan)
			}
			c.receivedPacketHandler.ReceivedPacket(extHdr.PacketNumber, protocol.ECNUnsupported, encLevel, time.Now(), true)
			c.ackMu.Unlock()
			c.scheduleSending() // Schedule an ACK
		} else { // Short Header Packet
			_, pn, pnLen, kp, err := wire.ParseShortHeader(data, c.destConnID.Len())
			if err != nil {
				continue
			}
			hdrLen := 1 + c.destConnID.Len() + int(pnLen)
			payload, err = c.shortHeaderOpener.Open(nil, data[hdrLen:], time.Now(), pn, kp, data[:hdrLen])
			if err != nil {
				continue
			}
			encLevel = protocol.Encryption1RTT

			c.ackMu.Lock()
			if !c.isClient && !c.initialKeysDropped {
				c.initialKeysDropped = true
				log.Printf("[%s] Received first 1-RTT packet. Dropping Initial packet space.", c.side())
				c.sentPacketHandler.DropPackets(protocol.EncryptionInitial, time.Now())
				c.receivedPacketHandler.DropPackets(protocol.EncryptionInitial)
			}
			c.receivedPacketHandler.ReceivedPacket(pn, protocol.ECNUnsupported, encLevel, time.Now(), true)
			c.ackMu.Unlock()
			c.scheduleSending() // Schedule an ACK
		}
		c.processFrames(frameParser, payload, encLevel)
		if handshakeCompletedInThisPacket {
			c.ackMu.Lock()
			c.sentPacketHandler.DropPackets(protocol.EncryptionInitial, time.Now())
			c.receivedPacketHandler.DropPackets(protocol.EncryptionInitial)
			c.initialKeysDropped = true
			log.Printf("[%s] Client confirmed handshake, dropping Initial packet space.", c.side())
			c.ackMu.Unlock()
		}
	}
}

// ... (processFrames and handleFrame remain mostly the same, just with more granular locking) ...
func (c *Connection) processFrames(frameParser *wire.FrameParser, payload []byte, encLevel protocol.EncryptionLevel) {
	frameData := payload
	for len(frameData) > 0 {
		bytesRead, frame, err := frameParser.ParseNext(frameData, encLevel, protocol.Version1)
		if err != nil {
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
				log.Printf("[%s] Accept queue full, dropping stream %d", c.side(), f.StreamID)
			}
		} else {
			stream.handleStreamFrame(f)
		}
	case *wire.AckFrame:
		c.ackMu.Lock()
		if _, err := c.sentPacketHandler.ReceivedAck(f, encLevel, time.Now()); err != nil {
			log.Printf("[%s] Error processing ACK frame: %v", c.side(), err)
		}
		c.ackMu.Unlock()
	case *wire.PingFrame:
		c.ackMu.Lock()
		if !c.isClient && !c.handshakeComplete {
			c.handshakeComplete = true
			log.Printf("[%s] Server handshake complete.", c.side())
			close(c.handshakeCompleteChan)
		}
		c.ackMu.Unlock()
	default:
		log.Printf("[%s] Ignoring frame of type %T", c.side(), f)
	}
}

// packerLoop replaces the old sendLoop. It's responsible for collecting frames
// and building packets, which are then handed off to the sender.
func (c *Connection) packerLoop(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	var handshakeTimerChan <-chan time.Time
	for {
		c.ackMu.Lock()
		if c.handshakeTimer != nil {
			handshakeTimerChan = c.handshakeTimer.C
		}
		c.ackMu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.sendingScheduled:
			// This is the trigger to start sending.
		case <-ticker.C:
			// The ticker is a fallback and also triggers loss detection.
			c.ackMu.Lock()
			if err := c.sentPacketHandler.OnLossDetectionTimeout(time.Now()); err != nil {
				c.ackMu.Unlock()
				return err
			}
			c.ackMu.Unlock()
		case <-handshakeTimerChan:
			c.ackMu.Lock()
			if !c.handshakeComplete {
				log.Printf("[%s] Handshake timeout, resending PING...", c.side())
				c.retransmissionQueue.Add(&wire.PingFrame{})
				c.handshakeTimer.Reset(c.handshakeTimeout)
				c.scheduleSending()
			}
			c.ackMu.Unlock()
		}

		// After any trigger, enter a busy loop to send as much as possible.
	busyLoop:
		for {
			// We're about to send, so drain any pending schedule signal to avoid redundant sends.
			select {
			case <-c.sendingScheduled:
			default:
			}

			// sendPackets now returns true if it sent at least one packet.
			if !c.sendPackets() {
				// No more data to send, break the busy loop and go back to waiting for a new signal.
				break busyLoop
			}
		}
	}
}

// sendPackets now just collects frames and calls packAndSendPacket.
// It returns true if it sent at least one packet.
func (c *Connection) sendPackets() bool {
	var sentAnyPacket bool
	var initialFrames, oneRTTFrames []wire.Frame

	// Get ACKs
	c.ackMu.Lock()
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, time.Now(), false); ack != nil {
		initialFrames = append(initialFrames, ack)
	}
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now(), false); ack != nil {
		oneRTTFrames = append(oneRTTFrames, ack)
	}
	isHandshakeComplete := c.handshakeComplete
	c.ackMu.Unlock()

	for c.retransmissionQueue.HasData() {
		frame := c.retransmissionQueue.GetFrame()
		if !isHandshakeComplete {
			if _, ok := frame.(*wire.PingFrame); ok {
				initialFrames = append(initialFrames, frame)
				continue
			}
		}
		oneRTTFrames = append(oneRTTFrames, frame)
	}

	// Pack and send initial packets
	for len(initialFrames) > 0 {
		raw, remaining, err := c.packAndSendPacket(initialFrames, protocol.EncryptionInitial)
		initialFrames = remaining
		if err != nil {
			log.Printf("Error packing initial packet: %v", err)
			break
		}
		if raw != nil {
			c.sendPackedPacket(raw)
			sentAnyPacket = true
		}
	}

	// Pack and send 1-RTT packets
	for len(oneRTTFrames) > 0 {
		raw, remaining, err := c.packAndSendPacket(oneRTTFrames, protocol.Encryption1RTT)
		oneRTTFrames = remaining
		if err != nil {
			log.Printf("Error packing 1-RTT packet: %v", err)
			break
		}
		if raw != nil {
			c.sendPackedPacket(raw)
			sentAnyPacket = true
		}
	}

	return sentAnyPacket
}

// packAndSendPacket now builds a packet and sends it to the sender queue.
// It returns the raw packet bytes and the frames that didn't fit.
func (c *Connection) packAndSendPacket(frames []wire.Frame, encLevel protocol.EncryptionLevel) ([]byte, []wire.Frame, error) {
	if len(frames) == 0 {
		return nil, nil, nil
	}

	c.ackMu.Lock()
	defer c.ackMu.Unlock()

	if encLevel == protocol.EncryptionInitial && c.initialKeysDropped {
		return nil, nil, nil
	}

	var payloadBytes []byte
	var ackFramesInPacket []ackhandler.Frame
	isAckEliciting := false
	handler := &retransmissionHandler{conn: c}
	var cutoff int

	// Determine max payload size
	var overhead int
	if encLevel == protocol.EncryptionInitial {
		overhead = c.longHeaderSealer.Overhead() + 20 // Approx for header fields
	} else {
		overhead = c.shortHeaderSealer.Overhead() + c.destConnID.Len() + 1 // Approx for header fields
	}
	_, pnLenForOverhead := c.sentPacketHandler.PeekPacketNumber(encLevel)
	overhead += int(pnLenForOverhead)

	maxPayloadSize := MaxPacketBufferSize - overhead

	for i, frame := range frames {
		frameLen := int(frame.Length(protocol.Version1))
		if len(payloadBytes)+frameLen > maxPayloadSize {
			if len(payloadBytes) == 0 {
				log.Printf("Frame of type %T with length %d is too large to fit in a packet with max size %d and was dropped.", frame, frameLen, maxPayloadSize)
				cutoff = i + 1
			}
			break
		}

		if _, isAck := frame.(*wire.AckFrame); !isAck {
			isAckEliciting = true
		}
		var err error
		payloadBytes, err = frame.Append(payloadBytes, protocol.Version1)
		if err != nil {
			return nil, nil, err
		}
		ackFramesInPacket = append(ackFramesInPacket, ackhandler.Frame{Frame: frame, Handler: handler})
		cutoff = i + 1
	}

	if len(ackFramesInPacket) == 0 {
		return nil, frames[cutoff:], nil
	}

	pn, pnLen := c.sentPacketHandler.PeekPacketNumber(encLevel)
	c.sentPacketHandler.PopPacketNumber(encLevel)

	var rawPacket []byte
	if encLevel == protocol.EncryptionInitial {
		hdr := &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: c.destConnID,
				SrcConnectionID:  c.destConnID,
				Length:           protocol.ByteCount(len(payloadBytes) + int(pnLen) + c.longHeaderSealer.Overhead()),
				Version:          protocol.Version1,
			},
			PacketNumber:    pn,
			PacketNumberLen: pnLen,
		}
		rawHdr, err := hdr.Append(nil, protocol.Version1)
		if err != nil {
			return nil, nil, err
		}
		payload := c.longHeaderSealer.Seal(nil, payloadBytes, pn, rawHdr)
		rawPacket = append(rawHdr, payload...)

		if c.isClient && !c.initialPacketSent {
			c.initialPacketSent = true
			c.handshakeTimer = time.NewTimer(c.handshakeTimeout)
		}
	} else { // 1-RTT
		rawHdr, err := wire.AppendShortHeader(nil, c.destConnID, pn, pnLen, c.shortHeaderSealer.KeyPhase())
		if err != nil {
			return nil, nil, err
		}
		payload := c.shortHeaderSealer.Seal(nil, payloadBytes, pn, rawHdr)
		rawPacket = append(rawHdr, payload...)
	}

	c.sentPacketHandler.SentPacket(
		time.Now(), pn, protocol.InvalidPacketNumber, nil, ackFramesInPacket,
		encLevel, protocol.ECNUnsupported, protocol.ByteCount(len(rawPacket)),
		isAckEliciting, false,
	)

	return rawPacket, frames[cutoff:], nil
}

func (c *Connection) sendPackedPacket(rawPacket []byte) {
	buffer := getPacketBuffer()
	buffer.Data = append(buffer.Data, rawPacket...)

	// This loop handles backpressure from the send queue.
	for {
		select {
		case <-c.ctx.Done():
			buffer.Release()
			return
		default:
		}

		if !c.sender.WouldBlock() {
			c.sender.Send(buffer)
			return // Packet sent successfully.
		}

		select {
		case <-c.sender.Available():
			continue
		case <-c.ctx.Done():
			buffer.Release()
			return
		}
	}
}

// ... (newStream, OpenStream, AcceptStream are mostly the same) ...
func (c *Connection) newStream(id protocol.StreamID) *Stream {
	fc := flowcontrol.NewStreamFlowController(
		id, c.connFlowController,
		protocol.DefaultInitialMaxStreamData, protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		protocol.ByteCount(protocol.DefaultInitialMaxStreamData),
		c.rttStats, c.logger,
	)
	return newStream(c.ctx, id, c, fc)
}

func (c *Connection) OpenStream(ctx context.Context) (*Stream, error) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	streamID := c.nextStreamID
	c.nextStreamID += 2
	stream := c.newStream(streamID)
	c.streams[streamID] = stream
	return stream, nil
}

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

// scheduleSending signals the packer loop that there's work to do.
func (c *Connection) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

// sendStreamData now adds the frame to the retransmission queue
// and signals the packer loop.
func (c *Connection) sendStreamData(id protocol.StreamID, data []byte, fin bool, offset protocol.ByteCount) {
	c.retransmissionQueue.Add(&wire.StreamFrame{
		StreamID: id, Offset: offset, Data: data, Fin: fin, DataLenPresent: true,
	})
	c.scheduleSending()
}

// Close now also closes the sender and is protected by sync.Once.
func (c *Connection) Close(err error) {
	c.closeOnce.Do(func() {
		c.cancel()
		c.sender.Close() // Gracefully close the sender
		c.transport.Close()
		c.streamsMu.RLock()
		defer c.streamsMu.RUnlock()
		for _, s := range c.streams {
			s.cancel(err)
		}
		close(c.closed)
	})
}

func (c *Connection) side() string {
	if c.isClient {
		return "CLIENT"
	}
	return "SERVER"
}
