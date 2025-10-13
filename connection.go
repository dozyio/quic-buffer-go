package quicbuffer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
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

var debugLog = log.New(io.Discard, "[SEND_DEBUG] ", log.Ltime|log.Lmicroseconds)

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

type Connection struct {
	transport              LowerLayerTransport
	isClient               bool
	ctx                    context.Context
	cancel                 context.CancelFunc
	destConnID             protocol.ConnectionID
	nextStreamID           protocol.StreamID
	streams                map[protocol.StreamID]*Stream
	streamsMu              sync.RWMutex
	acceptQueue            chan *Stream
	sentPacketHandler      ackhandler.SentPacketHandler
	receivedPacketHandler  ackhandler.ReceivedPacketHandler
	ackMu                  sync.Mutex
	congestionController   congestion.SendAlgorithmWithDebugInfos
	connFlowController     flowcontrol.ConnectionFlowController
	rttStats               *utils.RTTStats
	longHeaderSealer       handshake.LongHeaderSealer
	longHeaderOpener       handshake.LongHeaderOpener
	shortHeaderSealer      handshake.ShortHeaderSealer
	shortHeaderOpener      handshake.ShortHeaderOpener
	sendQueue              chan wire.Frame
	retransmissionQueue    *retransmissionQueue
	logger                 utils.Logger
	handshakeComplete      bool
	handshakeCompleteChan  chan struct{}
	handshakeTimer         *time.Timer
	handshakeTimeout       time.Duration
	initialKeysDropped     bool
	sendingScheduled       chan struct{}
	initialPacketSent      bool
	idleTimeout            time.Duration
	keepAliveInterval      time.Duration
	lastPacketReceivedTime time.Time
	keepAlivePingSent      bool
	closeOnce              sync.Once
	closeErr               error
}

func NewConnection(transport LowerLayerTransport, isClient bool) (*Connection, error) {
	connID, err := protocol.GenerateConnectionID(8)
	if err != nil {
		return nil, err
	}

	logger := &dummyLogger{}
	rttStats := &utils.RTTStats{}
	perspective := protocol.PerspectiveClient
	if !isClient {
		perspective = protocol.PerspectiveServer
	}
	c := &Connection{
		transport:              transport,
		isClient:               isClient,
		destConnID:             connID,
		streams:                make(map[protocol.StreamID]*Stream),
		acceptQueue:            make(chan *Stream, 10),
		rttStats:               rttStats,
		longHeaderSealer:       &nullLongHeaderAEAD{},
		longHeaderOpener:       &nullLongHeaderAEAD{},
		shortHeaderSealer:      &nullShortHeaderAEAD{},
		shortHeaderOpener:      &nullShortHeaderAEAD{},
		sendQueue:              make(chan wire.Frame, 10000),
		logger:                 logger,
		handshakeCompleteChan:  make(chan struct{}),
		handshakeTimeout:       1 * time.Second,
		sendingScheduled:       make(chan struct{}, 1),
		idleTimeout:            DefaultIdleTimeout,
		keepAliveInterval:      DefaultIdleTimeout / 2,
		lastPacketReceivedTime: time.Now(),
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
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

func (c *Connection) Run(ctx context.Context) error {
	errChan := make(chan error, 2)

	go func() {
		// This goroutine runs until the connection's internal c.ctx is canceled.
		err := c.receiveLoop(c.ctx)
		// Don't send an error if it's a standard closure.
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			errChan <- err
		} else {
			errChan <- nil // Signal graceful exit
		}
	}()

	go func() {
		err := c.sendLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			errChan <- err
		} else {
			errChan <- nil // Signal graceful exit
		}
	}()

	// Wait for the first loop to exit, which will trigger a close.
	firstErr := <-errChan
	// Now that one loop has exited (likely by calling c.Close), the other will exit shortly.
	// Calling c.Close() ensures a clean shutdown if the exit was triggered by the external context.
	c.Close(firstErr)

	// Wait for the second loop to finish exiting.
	<-errChan

	// If the external context was canceled, that's the primary reason for shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Return the error that initiated the close.
	return c.closeErr
}

func (c *Connection) receiveLoop(ctx context.Context) error {
	frameParser := wire.NewFrameParser(false, true)
	for {
		data, err := c.transport.ReadPacket()
		if err != nil {
			return err
		}

		c.ackMu.Lock()
		c.lastPacketReceivedTime = time.Now()
		c.keepAlivePingSent = false
		c.ackMu.Unlock()

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

			err = c.receivedPacketHandler.ReceivedPacket(extHdr.PacketNumber, protocol.ECNUnsupported, encLevel, time.Now(), true)
			if err != nil {
				log.Printf("[%s] Error processing packet: %v", c.side(), err)
				c.ackMu.Unlock()
				continue
			}
			c.ackMu.Unlock()
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
				c.sentPacketHandler.DropPackets(protocol.EncryptionInitial, time.Now())
				c.receivedPacketHandler.DropPackets(protocol.EncryptionInitial)
				c.initialKeysDropped = true
				log.Printf("[%s] Received first 1-RTT packet. Dropping Initial packet space.", c.side())
			}
			err = c.receivedPacketHandler.ReceivedPacket(pn, protocol.ECNUnsupported, encLevel, time.Now(), true)
			if err != nil {
				log.Printf("[%s] Error processing packet: %v", c.side(), err)
			}
			c.ackMu.Unlock()
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

func (c *Connection) processFrames(frameParser *wire.FrameParser, payload []byte, encLevel protocol.EncryptionLevel) {
	frameData := payload
	for len(frameData) > 0 {
		bytesRead, frame, err := frameParser.ParseNext(frameData, encLevel, protocol.Version2)
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

func (c *Connection) sendLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
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
			// A signal means there's new data. Try to send immediately.
			if err := c.sendPackets(); err != nil {
				return err
			}
		case <-ticker.C:
			// The ticker is our periodic check for loss detection and keep-alives.
			c.ackMu.Lock()
			if err := c.sentPacketHandler.OnLossDetectionTimeout(time.Now()); err != nil {
				c.ackMu.Unlock()
				return err
			}

			idleDuration := time.Since(c.lastPacketReceivedTime)
			if idleDuration > c.idleTimeout {
				c.ackMu.Unlock()
				err := errors.New("idle timeout")
				c.Close(err)
				return err
			}

			if idleDuration > c.keepAliveInterval && !c.keepAlivePingSent {
				c.sendQueue <- &wire.PingFrame{}
				c.scheduleSending()
				c.keepAlivePingSent = true
			}
			c.ackMu.Unlock()

			// After handling timers, try to send any pending packets.
			if err := c.sendPackets(); err != nil {
				return err
			}
		case <-handshakeTimerChan:
			c.ackMu.Lock()
			if !c.handshakeComplete {
				c.sendQueue <- &wire.PingFrame{}
				c.handshakeTimer.Reset(c.handshakeTimeout)
				c.scheduleSending()
			}
			c.ackMu.Unlock()
		}
	}
}

func (c *Connection) sendPackets() error {
	var initialFrames, oneRTTFrames []wire.Frame
	c.ackMu.Lock()
	// This function will now attempt to send only ONE packet per encryption level per call.
	sendMode := c.sentPacketHandler.SendMode(time.Now())
	debugLog.Printf("sendPackets called. Send mode: %s", sendMode)

	if sendMode == ackhandler.SendNone || sendMode == ackhandler.SendPacingLimited {
		c.ackMu.Unlock()
		if sendMode == ackhandler.SendPacingLimited {
			debugLog.Printf("Pacing limited. Not sending.")
		}
		return nil
	}

	// Gather frames based on send mode
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, time.Now(), false); ack != nil {
		initialFrames = append(initialFrames, ack)
	}
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now(), false); ack != nil {
		oneRTTFrames = append(oneRTTFrames, ack)
	}

	if sendMode != ackhandler.SendAck {
		if c.retransmissionQueue.HasData() {
			frame := c.retransmissionQueue.GetFrame()
			debugLog.Printf("Popped retransmission frame: %T", frame)
			oneRTTFrames = append(oneRTTFrames, frame)
		}
	DrainNewData:
		for {
			select {
			case frame := <-c.sendQueue:
				debugLog.Printf("Popped new frame from sendQueue: %T", frame)
				if !c.handshakeComplete {
					if _, ok := frame.(*wire.PingFrame); ok {
						initialFrames = append(initialFrames, frame)
					} else {
						oneRTTFrames = append(oneRTTFrames, frame)
					}
				} else {
					oneRTTFrames = append(oneRTTFrames, frame)
				}
			default:
				break DrainNewData
			}
		}
	}
	c.ackMu.Unlock()

	if len(initialFrames) > 0 {
		debugLog.Printf("Attempting to send INITIAL packet with %d frames.", len(initialFrames))
		if _, err := c.packAndSendPacket(initialFrames, protocol.EncryptionInitial); err != nil {
			return err
		}
	}

	if len(oneRTTFrames) > 0 {
		debugLog.Printf("Attempting to send 1-RTT packet with %d frames.", len(oneRTTFrames))
		if _, err := c.packAndSendPacket(oneRTTFrames, protocol.Encryption1RTT); err != nil {
			return err
		}
	}
	return nil
}

func (c *Connection) packAndSendPacket(frames []wire.Frame, encLevel protocol.EncryptionLevel) ([]wire.Frame, error) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()

	if encLevel == protocol.EncryptionInitial && c.initialKeysDropped {
		return nil, nil
	}

	pn, pnLen := c.sentPacketHandler.PeekPacketNumber(encLevel)

	var hdrLen, overhead int
	if encLevel == protocol.EncryptionInitial {
		overhead = c.longHeaderSealer.Overhead()
		// Use a safe, static approximation for Initial packet headers.
		// 1 (type) + 4 (version) + 1 (DCID len) + 8 (DCID) + 1 (SCID len) + 8 (SCID) + 2 (token len) + 2 (len) + 4 (PN) = 31
		hdrLen = 31
	} else {
		overhead = c.shortHeaderSealer.Overhead()
		hdrLen = 1 + c.destConnID.Len() + int(pnLen)
	}
	maxPayloadSize := InitialPacketSize - hdrLen - overhead
	debugLog.Printf("PACKER [%s]: maxPacketSize: %d, hdrLen: %d, overhead: %d, maxPayloadSize: %d", encLevel, InitialPacketSize, hdrLen, overhead, maxPayloadSize)

	var payloadLength int
	var framesInPacket []wire.Frame
	var ackFramesInPacket []ackhandler.Frame
	var cutoff int
	isAckEliciting := false
	handler := c.retransmissionQueue.FrameHandler(encLevel)

	remainingFrames := frames
	for i, frame := range remainingFrames {
		frameLen := int(frame.Length(protocol.Version2))
		debugLog.Printf("PACKER: Considering frame %T with length %d. Current payload: %d", frame, frameLen, payloadLength)

		if payloadLength+frameLen > maxPayloadSize {
			debugLog.Printf("PACKER: Frame %T does not fit (payload %d + frame %d > max %d)", frame, payloadLength, frameLen, maxPayloadSize)
			if streamFrame, ok := frame.(*wire.StreamFrame); ok && len(framesInPacket) == 0 {
				debugLog.Printf("PACKER: Attempting to split oversized stream frame.")
				splitFrame, wasSplit := streamFrame.MaybeSplitOffFrame(protocol.ByteCount(maxPayloadSize-payloadLength), protocol.Version2)
				if wasSplit && splitFrame != nil {
					debugLog.Printf("PACKER: Successfully split frame. New chunk size: %d", splitFrame.DataLen())
					framesInPacket = append(framesInPacket, splitFrame)
					ackFramesInPacket = append(ackFramesInPacket, ackhandler.Frame{Frame: splitFrame, Handler: handler})
					isAckEliciting = true
				} else {
					debugLog.Printf("PACKER: Failed to split frame (not enough space for even a minimal frame).")
				}
			}
			break
		}

		payloadLength += frameLen
		framesInPacket = append(framesInPacket, frame)
		if _, isAck := frame.(*wire.AckFrame); !isAck {
			isAckEliciting = true
		}
		ackFramesInPacket = append(ackFramesInPacket, ackhandler.Frame{Frame: frame, Handler: handler})
		cutoff = i + 1
	}

	if len(framesInPacket) == 0 {
		if len(frames) > 0 {
			debugLog.Printf("PACKER: No frames packed. First pending frame is %T with length %d.", frames[0], frames[0].Length(protocol.Version2))
		}
		return frames, nil
	}

	c.sentPacketHandler.PopPacketNumber(encLevel)
	// ... (rest of the function is the same as the last version) ...
	// ... from payloadBuf := getPacketBuffer() ...
	payloadBuf := getPacketBuffer()
	defer putPacketBuffer(payloadBuf)
	for _, frame := range framesInPacket {
		b, err := frame.Append(payloadBuf.Bytes(), protocol.Version2)
		if err != nil {
			return nil, err
		}
		payloadBuf.Reset()
		payloadBuf.Write(b)
	}

	var raw, payload []byte
	var err error

	if encLevel == protocol.EncryptionInitial {
		hdr := &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: c.destConnID,
				SrcConnectionID:  c.destConnID,
				Length:           protocol.ByteCount(payloadBuf.Len() + int(pnLen) + overhead),
				Version:          protocol.Version2,
			},
			PacketNumber:    pn,
			PacketNumberLen: pnLen,
		}
		raw, err = hdr.Append(nil, protocol.Version2)
		if err != nil {
			return nil, err
		}
		payload = payloadBuf.Bytes()
		if c.isClient && !c.initialPacketSent {
			c.initialPacketSent = true
			c.handshakeTimer = time.NewTimer(c.handshakeTimeout)
			log.Printf("[%s] Initial packet sent. Handshake timer started.", c.side())
		}
	} else {
		raw, err = wire.AppendShortHeader(nil, c.destConnID, pn, pnLen, c.shortHeaderSealer.KeyPhase())
		if err != nil {
			return nil, err
		}
		payload = payloadBuf.Bytes()
	}

	// Unlock before network write
	c.ackMu.Unlock()
	raw = append(raw, payload...)
	writeErr := c.transport.WritePacket(raw)
	// Re-acquire lock to update state
	c.ackMu.Lock()
	if writeErr != nil {
		return nil, writeErr
	}

	debugLog.Printf("PACKER: Sent packet %d at level %s with %d frames, total size %d.", pn, encLevel, len(framesInPacket), len(raw))

	c.sentPacketHandler.SentPacket(
		time.Now(), pn, protocol.InvalidPacketNumber, nil, ackFramesInPacket,
		encLevel, protocol.ECNUnsupported, protocol.ByteCount(len(raw)),
		isAckEliciting, false,
	)

	return remainingFrames[cutoff:], nil
}

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

func (c *Connection) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

func (c *Connection) sendStreamData(id protocol.StreamID, data []byte, fin bool, offset protocol.ByteCount) {
	c.sendQueue <- &wire.StreamFrame{
		StreamID: id, Offset: offset, Data: data, Fin: fin, DataLenPresent: true,
	}
	c.scheduleSending()
}

func (c *Connection) Close(err error) {
	c.closeOnce.Do(func() {
		c.closeErr = err
	})

	c.cancel()
	c.transport.Close()
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	for _, s := range c.streams {
		s.cancel(err)
	}
}

func (c *Connection) side() string {
	if c.isClient {
		return "CLIENT"
	}
	return "SERVER"
}

var packetBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func getPacketBuffer() *bytes.Buffer {
	buf, ok := packetBufferPool.Get().(*bytes.Buffer)
	if !ok {
		return nil
	}

	return buf
}

func putPacketBuffer(buf *bytes.Buffer) {
	buf.Reset()
	packetBufferPool.Put(buf)
}
