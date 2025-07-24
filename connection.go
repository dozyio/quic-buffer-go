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
	transport             LowerLayerTransport
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
	ackMu                 sync.Mutex
	congestionController  congestion.SendAlgorithmWithDebugInfos
	connFlowController    flowcontrol.ConnectionFlowController
	rttStats              *utils.RTTStats
	longHeaderSealer      handshake.LongHeaderSealer
	longHeaderOpener      handshake.LongHeaderOpener
	shortHeaderSealer     handshake.ShortHeaderSealer
	shortHeaderOpener     handshake.ShortHeaderOpener
	sendQueue             chan wire.Frame
	retransmissionQueue   *retransmissionQueue
	logger                utils.Logger
	handshakeComplete     bool
	handshakeCompleteChan chan struct{}
	handshakeTimer        *time.Timer
	handshakeTimeout      time.Duration
	initialKeysDropped    bool
	sendingScheduled      chan struct{}
	initialPacketSent     bool
}

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
		logger:                logger,
		handshakeCompleteChan: make(chan struct{}),
		handshakeTimeout:      1 * time.Second,
		sendingScheduled:      make(chan struct{}, 1),
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

func (c *Connection) receiveLoop(ctx context.Context) error {
	frameParser := wire.NewFrameParser(false, true)
	for {
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
			c.receivedPacketHandler.ReceivedPacket(pn, protocol.ECNUnsupported, encLevel, time.Now(), true)
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
			if err := c.sendPackets(); err != nil {
				return err
			}
		case <-ticker.C:
			c.ackMu.Lock()
			if err := c.sentPacketHandler.OnLossDetectionTimeout(time.Now()); err != nil {
				c.ackMu.Unlock()
				return err
			}
			c.ackMu.Unlock()
			if err := c.sendPackets(); err != nil {
				return err
			}
		case <-handshakeTimerChan:
			c.ackMu.Lock()
			if !c.handshakeComplete {
				log.Printf("[%s] Handshake timeout, resending PING...", c.side())
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
	isHandshakeComplete := c.handshakeComplete
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, time.Now(), false); ack != nil {
		initialFrames = append(initialFrames, ack)
	}
	if ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, time.Now(), false); ack != nil {
		oneRTTFrames = append(oneRTTFrames, ack)
	}
	c.ackMu.Unlock()
	for c.retransmissionQueue.HasData() {
		oneRTTFrames = append(oneRTTFrames, c.retransmissionQueue.GetFrame())
	}
DrainNewData:
	for {
		select {
		case frame := <-c.sendQueue:
			if !isHandshakeComplete {
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
	if len(initialFrames) > 0 {
		for len(initialFrames) > 0 {
			var err error
			initialFrames, err = c.packAndSendPacket(initialFrames, protocol.EncryptionInitial)
			if err != nil {
				return err
			}
		}
	}
	if len(oneRTTFrames) > 0 {
		for len(oneRTTFrames) > 0 {
			var err error
			oneRTTFrames, err = c.packAndSendPacket(oneRTTFrames, protocol.Encryption1RTT)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Connection) packAndSendPacket(frames []wire.Frame, encLevel protocol.EncryptionLevel) ([]wire.Frame, error) {
	c.ackMu.Lock()
	if encLevel == protocol.EncryptionInitial && c.initialKeysDropped {
		c.ackMu.Unlock()
		return nil, nil
	}
	pn, pnLen := c.sentPacketHandler.PeekPacketNumber(encLevel)
	c.sentPacketHandler.PopPacketNumber(encLevel)
	c.ackMu.Unlock()
	var payloadLength int
	var framesInPacket []wire.Frame
	var ackFramesInPacket []ackhandler.Frame
	var cutoff int
	isAckEliciting := false
	maxPacketSize := protocol.InitialPacketSize - 40
	handler := c.retransmissionQueue.FrameHandler(encLevel)
	for i, frame := range frames {
		if _, isAck := frame.(*wire.AckFrame); !isAck {
			isAckEliciting = true
		}
		frameLen := int(frame.Length(protocol.Version2))
		if payloadLength+frameLen > maxPacketSize && payloadLength > 0 {
			break
		}
		payloadLength += frameLen
		framesInPacket = append(framesInPacket, frame)
		ackFramesInPacket = append(ackFramesInPacket, ackhandler.Frame{Frame: frame, Handler: handler})
		cutoff = i + 1
	}
	if len(framesInPacket) == 0 {
		return frames[cutoff:], nil
	}
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
	var overhead int
	var err error
	if encLevel == protocol.EncryptionInitial {
		overhead = c.longHeaderSealer.Overhead()
		hdr := &wire.ExtendedHeader{
			Header: wire.Header{
				Type: protocol.PacketTypeInitial, DestConnectionID: c.destConnID, SrcConnectionID: c.destConnID,
				Length:  protocol.ByteCount(payloadBuf.Len() + int(pnLen) + overhead),
				Version: protocol.Version2,
			},
			PacketNumber: pn, PacketNumberLen: pnLen,
		}
		raw, err = hdr.Append(nil, protocol.Version2)
		payload = c.longHeaderSealer.Seal(nil, payloadBuf.Bytes(), pn, raw)
		c.ackMu.Lock()
		if c.isClient && !c.initialPacketSent {
			c.initialPacketSent = true
			c.handshakeTimer = time.NewTimer(c.handshakeTimeout)
			log.Printf("[%s] Initial packet sent. Handshake timer started.", c.side())
		}
		c.ackMu.Unlock()
	} else {
		overhead = c.shortHeaderSealer.Overhead()
		raw, err = wire.AppendShortHeader(nil, c.destConnID, pn, pnLen, c.shortHeaderSealer.KeyPhase())
		payload = c.shortHeaderSealer.Seal(nil, payloadBuf.Bytes(), pn, raw)
	}
	if err != nil {
		return nil, err
	}
	c.ackMu.Lock()
	c.sentPacketHandler.SentPacket(
		time.Now(), pn, protocol.InvalidPacketNumber, nil, ackFramesInPacket,
		encLevel, protocol.ECNUnsupported, protocol.ByteCount(payloadBuf.Len()+len(raw)+overhead),
		isAckEliciting, false,
	)
	c.ackMu.Unlock()
	raw = append(raw, payload...)
	if err := c.transport.WritePacket(raw); err != nil {
		return nil, err
	}
	return frames[cutoff:], nil
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

func getPacketBuffer() *bytes.Buffer { return packetBufferPool.Get().(*bytes.Buffer) }
func putPacketBuffer(buf *bytes.Buffer) {
	buf.Reset()
	packetBufferPool.Put(buf)
}
