package quicbuffer

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dozyio/quic-buffer-go/internal/ackhandler"
	"github.com/dozyio/quic-buffer-go/internal/congestion"
	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/handshake"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/utils"
	"github.com/dozyio/quic-buffer-go/internal/wire"
	"github.com/dozyio/quic-buffer-go/logging"
)

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

type realLogger struct{ prefix string }

func (l *realLogger) DropPacket(ptype protocol.PacketType, pn protocol.PacketNumber, reason string) {
	log.Printf("%s Dropped packet %d (%s): %s", l.prefix, pn, ptype, reason)
}

func (l *realLogger) Debugf(format string, args ...any) {
	log.Printf(l.prefix+" "+format, args...)
}

func (l *realLogger) Infof(format string, args ...any) {
	log.Printf(l.prefix+" "+format, args...)
}

func (l *realLogger) Errorf(format string, args ...any) {
	log.Printf(l.prefix+" "+format, args...)
}

func (l *realLogger) WithPrefix(prefix string) utils.Logger {
	return &realLogger{prefix: l.prefix + " " + prefix}
}
func (l *realLogger) Debug() bool                      { return true }
func (l *realLogger) SetLogLevel(level utils.LogLevel) {}
func (l *realLogger) SetLogTimeFormat(format string)   {}

type closeError struct {
	err       error
	immediate bool
}

type Connection struct {
	transport  LowerLayerTransport
	isClient   bool
	ctx        context.Context
	cancel     context.CancelFunc
	destConnID protocol.ConnectionID

	// nextStreamID          protocol.StreamID
	// streams               map[protocol.StreamID]*Stream
	// streamsMu             sync.RWMutex

	streamsMap *streamsMap

	// acceptQueue           chan *Stream
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	ackMu                 sync.Mutex
	congestionController  congestion.SendAlgorithmWithDebugInfos
	connFlowController    flowcontrol.ConnectionFlowController
	rttStats              *utils.RTTStats
	longHeaderSealer      handshake.LongHeaderSealer
	longHeaderOpener      handshake.LongHeaderOpener
	shortHeaderSealer     handshake.ShortHeaderSealer
	shortHeaderOpener     handshake.ShortHeaderOpener
	// sendQueue             chan wire.Frame
	framer                *framer
	retransmissionQueue   *retransmissionQueue
	logger                utils.Logger
	handshakeComplete     bool
	handshakeCompleteChan chan struct{}
	handshakeTimer        *time.Timer
	handshakeTimeout      time.Duration
	initialKeysDropped    bool
	sendingScheduled      chan struct{}
	initialPacketSent     bool

	closeChan chan struct{}
	closeErr  atomic.Pointer[closeError]
	closeOnce sync.Once

	// idle
	idleTimeout            time.Duration
	lastPacketReceivedTime time.Time

	// keep-alive
	keepAliveInterval time.Duration
	keepAlivePingSent bool

	streamAccessMu sync.Mutex
}

func NewConnection(transport LowerLayerTransport, isClient bool, tracer *logging.ConnectionTracer) (*Connection, error) {
	connID, err := protocol.GenerateConnectionID(8)
	if err != nil {
		return nil, err
	}

	logger := &realLogger{}
	rttStats := &utils.RTTStats{}
	perspective := protocol.PerspectiveClient
	if !isClient {
		perspective = protocol.PerspectiveServer
	}
	c := &Connection{
		transport:  transport,
		isClient:   isClient,
		destConnID: connID,
		// streams:                make(map[protocol.StreamID]*Stream),
		// acceptQueue:       make(chan *Stream, 10),
		rttStats:          rttStats,
		longHeaderSealer:  &nullLongHeaderAEAD{},
		longHeaderOpener:  &nullLongHeaderAEAD{},
		shortHeaderSealer: &nullShortHeaderAEAD{},
		shortHeaderOpener: &nullShortHeaderAEAD{},
		// sendQueue:              make(chan wire.Frame, 10000),
		logger:                 logger,
		handshakeCompleteChan:  make(chan struct{}),
		handshakeTimeout:       1 * time.Second,
		sendingScheduled:       make(chan struct{}, 1),
		idleTimeout:            DefaultIdleTimeout,
		keepAliveInterval:      DefaultIdleTimeout / 2,
		lastPacketReceivedTime: time.Now(),
		closeChan:              make(chan struct{}, 1),
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		func(protocol.ByteCount) bool { return true },
		c.rttStats,
		c.logger,
	)

	c.connFlowController.UpdateSendWindow(protocol.DefaultInitialMaxData)

	c.framer = newFramer(c.connFlowController)

	c.streamsMap = newStreamsMap(
		c.ctx,
		c,
		c.framer.QueueControlFrame,
		func(id protocol.StreamID) flowcontrol.StreamFlowController {
			return flowcontrol.NewStreamFlowController(
				id,
				c.connFlowController,
				protocol.DefaultInitialMaxStreamData,
				protocol.DefaultMaxReceiveConnectionFlowControlWindow,
				protocol.DefaultInitialMaxStreamData,
				c.rttStats,
				c.logger,
			)
		},
		protocol.DefaultMaxIncomingStreams,
		protocol.DefaultMaxIncomingUniStreams,
		perspective,
	)

	// This simulates the transport parameters being known immediately.
	c.streamsMap.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
		Type:         protocol.StreamTypeBidi,
		MaxStreamNum: 100,
	})
	c.streamsMap.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
		Type:         protocol.StreamTypeUni,
		MaxStreamNum: 100,
	})

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.retransmissionQueue = newRetransmissionQueue(c)
	c.congestionController = congestion.NewCubicSender(congestion.DefaultClock{}, c.rttStats, protocol.InitialPacketSize, true, nil)

	sentPacketHandler, receivedPacketHandler := ackhandler.NewAckHandler(0, protocol.InitialPacketSize, c.rttStats, !isClient, false, perspective, tracer, c.logger)
	c.sentPacketHandler = sentPacketHandler
	c.receivedPacketHandler = receivedPacketHandler

	if isClient {
		// A client should immediately start the handshake.
		// We queue a PING frame to serve as the ClientHello.
		c.framer.QueueControlFrame(&wire.PingFrame{})
		// And we schedule a send to wake up the sendLoop immediately.
		c.scheduleSending()
	}

	return c, nil
}

func (c *Connection) Run(ctx context.Context) error {
	errChan := make(chan error, 2)

	go func() {
		// This goroutine runs until the connection's internal c.ctx is canceled.
		err := c.receiveLoop(c.ctx)
		// Don't send an error if it's a standard closure.
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			errChan <- err
		} else {
			errChan <- nil // Signal graceful exit
		}
	}()

	go func() {
		err := c.sendLoop(c.ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			errChan <- err
		} else {
			errChan <- nil // Signal graceful exit
		}
	}()

	// Wait for the first of the two loops to exit.
	err := <-errChan
	// Now that one loop has exited (likely by calling c.Close), the other will exit shortly.
	// Calling c.Close() ensures a clean shutdown if the exit was triggered by the external context.
	c.Close(err)

	// Wait for the second loop to finish exiting.
	<-errChan

	// If the test context was canceled, that's the primary reason for shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Otherwise, return the actual error from the loop (which could be nil).
	return err
}

func (c *Connection) receiveLoop(ctx context.Context) error {
	frameParser := wire.NewFrameParser(false, true)
	for {
		// Read from the transport
		data, err := c.transport.ReadPacket()
		if err != nil {
			c.logger.Debugf("Error reading packet: %v", err)
			return err
		}
		c.logger.Debugf("<- Received packet (%d bytes)", len(data))

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
				c.logger.Debugf("Failed to parse long header packet: %v", err)
				continue
			}

			extHdr, err := hdr.ParseExtended(data)
			if err != nil {
				c.logger.Debugf("Failed to parse extended header: %v", err)
				continue
			}
			c.logger.Debugf("Parsed Long Header packet, PN: %d", extHdr.PacketNumber)

			payload, err = c.longHeaderOpener.Open(nil, packetData[extHdr.ParsedLen():], extHdr.PacketNumber, packetData[:extHdr.ParsedLen()])
			if err != nil {
				c.logger.Debugf("Failed to open long header packet: %v", err)
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
				c.logger.Debugf("Failed to parse short header packet: %v", err)
				continue
			}
			hdrLen := 1 + c.destConnID.Len() + int(pnLen)
			payload, err = c.shortHeaderOpener.Open(nil, data[hdrLen:], time.Now(), pn, kp, data[:hdrLen])
			if err != nil {
				c.logger.Debugf("Failed to open short header packet: %v", err)
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

			c.scheduleSending()
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
	// TODO: handle STREAM and ACK before calling handleFrame. Let this handle control frames only

	wire.LogFrame(c.logger, frame, false)
	switch f := frame.(type) {
	case *wire.StreamFrame:
		// Delegate to the streamsMap
		c.streamAccessMu.Lock()
		err := c.streamsMap.HandleStreamFrame(f, time.Now())
		c.streamAccessMu.Unlock()
		if err != nil {
			// Handle error, e.g., close the connection
			log.Printf("[%s] Error handling STREAM frame: %v", c.side(), err)
		}
	case *wire.ResetStreamFrame:
		c.streamAccessMu.Lock()
		err := c.streamsMap.HandleResetStreamFrame(f, time.Now())
		c.streamAccessMu.Unlock()
		if err != nil {
			log.Printf("[%s] Error handling RESET_STREAM frame: %v", c.side(), err)
		}
	case *wire.StopSendingFrame:
		c.streamAccessMu.Lock()
		err := c.streamsMap.HandleStopSendingFrame(f)
		c.streamAccessMu.Unlock()
		if err != nil {
			log.Printf("[%s] Error handling STOP_SENDING frame: %v", c.side(), err)
		}
	case *wire.MaxStreamsFrame:
		c.streamAccessMu.Lock()
		c.streamsMap.HandleMaxStreamsFrame(f)
		c.streamAccessMu.Unlock()
	case *wire.MaxDataFrame:
		log.Printf("[FLOW] Received MAX_DATA: MaximumData=%d", f.MaximumData)
		c.streamAccessMu.Lock()
		c.connFlowController.UpdateSendWindow(f.MaximumData)
		c.streamAccessMu.Unlock()
	case *wire.MaxStreamDataFrame:
		log.Printf("[FLOW] Received MAX_STREAM_DATA: StreamID=%d, MaximumData=%d", f.StreamID, f.MaximumStreamData)
		c.streamAccessMu.Lock()
		err := c.streamsMap.HandleMaxStreamDataFrame(f)
		c.streamAccessMu.Unlock()
		if err != nil {
			log.Printf("[%s] Error handling MAX_STREAM_DATA frame: %v", c.side(), err)
		}
	case *wire.AckFrame:
		c.ackMu.Lock()
		if c.isClient && !c.handshakeComplete {
			c.handshakeComplete = true
			log.Printf("[%s] Client confirmed handshake, dropping Initial packet space.", c.side())
			close(c.handshakeCompleteChan)

		}
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
			c.scheduleSending()
		}
		c.ackMu.Unlock()
	case *wire.DataBlockedFrame:
		// No action needed for this frame, but we don't want to log it as "ignoring".
	default:
		log.Printf("[%s] Ignoring frame of type %T", c.side(), f)
	}
}

func (c *Connection) sendLoop(ctx context.Context) error {
	// A single, dynamic timer is more efficient than a fixed-rate ticker.
	timer := time.NewTimer(0)
	// We want to send immediately on the first run, so we'll drain the timer
	// to ensure the select block doesn't wait.
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}

	for {
		// Before sleeping, always check if we should send packets immediately.
		// This is the key to avoiding the startup deadlock.
		if err := c.sendPackets(); err != nil {
			return err
		}

		// Now, determine the next deadline to sleep until.
		var nextDeadline time.Time
		c.ackMu.Lock()

		lossTime := c.sentPacketHandler.GetLossDetectionTimeout()
		ackTime := c.receivedPacketHandler.GetAlarmTimeout()

		// The next deadline is the earliest of the ACK timer and the loss timer.
		if !lossTime.IsZero() && (ackTime.IsZero() || lossTime.Before(ackTime)) {
			nextDeadline = lossTime
		} else {
			nextDeadline = ackTime
		}

		// If no packets are in flight, the next event is the idle keep-alive.
		hasInFlightPackets := !lossTime.IsZero()
		if !hasInFlightPackets {
			idleDeadline := c.lastPacketReceivedTime.Add(c.keepAliveInterval)
			if nextDeadline.IsZero() || idleDeadline.Before(nextDeadline) {
				nextDeadline = idleDeadline
			}
		}
		c.ackMu.Unlock()

		// Set the timer to the earliest deadline.
		if nextDeadline.IsZero() {
			timer.Stop()
		} else {
			timer.Reset(time.Until(nextDeadline))
		}

		// Use the nil-channel idiom to safely handle the handshake timer.
		var handshakeTimerChan <-chan time.Time
		c.ackMu.Lock()
		if c.handshakeTimer != nil {
			handshakeTimerChan = c.handshakeTimer.C
		}
		c.ackMu.Unlock()

		// Wait for the next event to occur.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.sendingScheduled:
			// A new packet was queued, loop around to send immediately.
			if !timer.Stop() {
				// Safely drain the timer if it fired concurrently.
				select {
				case <-timer.C:
				default:
				}
			}
			continue // Go to the top of the loop to send immediately
		case <-handshakeTimerChan:
			c.ackMu.Lock()
			if !c.handshakeComplete {
				log.Printf("[%s] Handshake timeout, resending PING...", c.side())
				c.framer.QueueControlFrame(&wire.PingFrame{})
				c.scheduleSending()
				c.handshakeTimer.Reset(c.handshakeTimeout)
			}
			c.ackMu.Unlock()
		case <-timer.C:
			// A deadline was reached (ACK, loss, or keep-alive).
			// We will handle the consequences after the select block.
		}

		// Now that we've been woken up, check what needs to be done.
		now := time.Now()
		c.ackMu.Lock()

		if err := c.sentPacketHandler.OnLossDetectionTimeout(now); err != nil {
			c.ackMu.Unlock()
			c.Close(err)
			return err
		}

		// Check for hard idle timeout.
		if now.After(c.lastPacketReceivedTime.Add(c.idleTimeout)) {
			c.ackMu.Unlock()
			err := errors.New("idle timeout")
			c.Close(err)
			return err
		}

		// Check if we need to send a keep-alive PING.
		lossTime = c.sentPacketHandler.GetLossDetectionTimeout()
		hasInFlightPackets = !lossTime.IsZero()
		if !hasInFlightPackets && now.After(c.lastPacketReceivedTime.Add(c.keepAliveInterval)) && !c.keepAlivePingSent {
			log.Printf("[%s] Sending keep-alive PING.", c.side())
			c.framer.QueueControlFrame(&wire.PingFrame{})
			c.scheduleSending()
			c.keepAlivePingSent = true
		}
		c.ackMu.Unlock()
	}
}

func (c *Connection) sendPackets() error {
	// 1. Before sending, queue any pending ACKs and retransmissions with the framer.
	// This ensures they are considered for inclusion in the next packet.
	c.ackMu.Lock()
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, time.Now(), false); ack != nil {
		c.framer.QueueControlFrame(ack)
	}
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now(), false); ack != nil {
		c.framer.QueueControlFrame(ack)
	}
	c.ackMu.Unlock()
	for c.retransmissionQueue.HasData() {
		c.framer.QueueControlFrame(c.retransmissionQueue.GetFrame())
	}

	// 2. The main sending loop.
	// This loop will create and send as many packets as necessary to drain the framer's queues.
	for {
		var sentPacket bool
		// Attempt to send one packet per active encryption level.
		if !c.initialKeysDropped {
			c.streamAccessMu.Lock()
			sent, err := c.packAndSendPacket(protocol.EncryptionInitial)
			c.streamAccessMu.Unlock()
			if err != nil {
				return err
			} else if sent {
				sentPacket = true
			}
		}
		if c.handshakeComplete {
			c.streamAccessMu.Lock()
			sent, err := c.packAndSendPacket(protocol.Encryption1RTT)
			c.streamAccessMu.Unlock()
			if err != nil {
				return err
			} else if sent {
				sentPacket = true
			}
		}
		// If we didn't send any packets in a full pass and the framer has no more data, we're done.
		if !sentPacket && !c.framer.HasData() {
			break
		}
	}
	return nil
}

// packAndSendPacket attempts to build and send a single packet for a specific encryption level.
// It returns true if a packet was successfully sent.
func (c *Connection) packAndSendPacket(encLevel protocol.EncryptionLevel) (bool, error) {
	if encLevel == protocol.EncryptionInitial && c.initialKeysDropped {
		return false, nil
	}

	var controlFrames []ackhandler.Frame
	var streamFrames []ackhandler.StreamFrame
	controlFrames, streamFrames, _ = c.framer.Append(controlFrames, streamFrames, protocol.InitialPacketSize, time.Now(), protocol.Version2)

	if len(controlFrames) == 0 && len(streamFrames) == 0 {
		return false, nil
	}

	c.ackMu.Lock()
	pn, pnLen := c.sentPacketHandler.PeekPacketNumber(encLevel)
	c.sentPacketHandler.PopPacketNumber(encLevel)
	c.ackMu.Unlock()

	buffer := getPacketBuffer()
	defer buffer.Release()

	// Serialize all frames directly into the buffer's Data slice.
	for _, f := range controlFrames {
		var err error
		buffer.Data, err = f.Frame.Append(buffer.Data, protocol.Version2)
		if err != nil {
			return false, err
		}
	}
	for _, f := range streamFrames {
		var err error
		buffer.Data, err = f.Frame.Append(buffer.Data, protocol.Version2)
		if err != nil {
			return false, err
		}
	}

	var raw []byte
	var overhead int
	var err error

	if encLevel == protocol.EncryptionInitial {
		overhead = c.longHeaderSealer.Overhead()
		hdr := &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: c.destConnID,
				SrcConnectionID:  c.destConnID,
				Length:           protocol.ByteCount(len(buffer.Data) + int(pnLen) + overhead),
				Version:          protocol.Version2,
			},
			PacketNumber:    pn,
			PacketNumberLen: pnLen,
		}
		raw, err = hdr.Append(nil, protocol.Version2)
		if err != nil {
			return false, err
		}
		if c.isClient && !c.initialPacketSent {
			c.initialPacketSent = true
			c.handshakeTimer = time.NewTimer(c.handshakeTimeout)
		}
	} else { // 1-RTT
		overhead = c.shortHeaderSealer.Overhead()
		raw, err = wire.AppendShortHeader(nil, c.destConnID, pn, pnLen, c.shortHeaderSealer.KeyPhase())
		if err != nil {
			return false, err
		}
	}

	c.ackMu.Lock()
	c.sentPacketHandler.SentPacket(
		time.Now(),
		pn,
		protocol.InvalidPacketNumber,
		streamFrames,
		controlFrames,
		encLevel,
		protocol.ECNUnsupported,
		protocol.ByteCount(len(buffer.Data)+len(raw)+overhead),
		false, // isPathMTUProbePacket
		false, // isPathProbePacket
	)
	c.ackMu.Unlock()

	raw = append(raw, buffer.Data...)
	if err := c.transport.WritePacket(raw); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Connection) OpenStream(ctx context.Context) (*Stream, error) {
	// The handshake waiting logic can be moved into the streamsMap if desired,
	// but for now, we keep it here for simplicity.
	select {
	case <-c.handshakeCompleteChan:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
	return c.streamsMap.OpenStream()
}

func (c *Connection) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.streamsMap.AcceptStream(ctx)
}

func (c *Connection) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

func (c *Connection) onHasConnectionData() {
	c.scheduleSending()
}

func (c *Connection) onHasStreamData(id protocol.StreamID, str *SendStream) {
	log.Printf("[CONN] Received onHasStreamData for Stream %d. Adding to framer.", id)
	c.framer.AddActiveStream(id, str)
	c.scheduleSending()
}

func (c *Connection) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	c.framer.AddStreamWithControlFrames(id, str)
	c.scheduleSending()
}

func (c *Connection) onStreamCompleted(id protocol.StreamID) {
	if err := c.streamsMap.DeleteStream(id); err != nil {
		c.closeLocal(err)
	}
	c.framer.RemoveActiveStream(id)
}

func (c *Connection) Close(err error) {
	c.closeOnce.Do(func() {
		c.cancel()
		c.transport.Close()
		if c.streamsMap != nil {
			c.streamsMap.CloseWithError(err)
		}
	})
}

// func (c *Connection) Close(err error) {
// 	c.cancel()
// 	c.transport.Close()
// 	if c.streamsMap != nil {
// 		c.streamsMap.CloseWithError(err)
// 	}
// }

// closeLocal closes the connection and send a CONNECTION_CLOSE containing the error
func (c *Connection) closeLocal(e error) {
	c.setCloseError(&closeError{err: e, immediate: false})
}

func (c *Connection) setCloseError(e *closeError) {
	c.closeErr.CompareAndSwap(nil, e)
	select {
	case c.closeChan <- struct{}{}:
	default:
	}
}

func (c *Connection) side() string {
	if c.isClient {
		return "CLIENT"
	}
	return "SERVER"
}

// var packetBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
//
// func getPacketBuffer() *bytes.Buffer {
// 	buf, ok := packetBufferPool.Get().(*bytes.Buffer)
// 	if !ok {
// 		return nil
// 	}
//
// 	return buf
// }
//
// func putPacketBuffer(buf *bytes.Buffer) {
// 	buf.Reset()
// 	packetBufferPool.Put(buf)
// }
