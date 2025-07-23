package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"sort"
	"sync"

	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

// Stream is the application-facing object for a single bidirectional stream.
type Stream struct {
	streamID protocol.StreamID
	conn     *Connection // The parent connection

	// Read-side
	readMu        sync.Mutex
	readBuffer    *bytes.Buffer
	readCond      *sync.Cond
	isFinished    bool
	readErr       error
	finalSize     protocol.ByteCount
	bytesRead     protocol.ByteCount
	readOffset    protocol.ByteCount
	receiveBuffer map[protocol.ByteCount][]byte

	// Write-side
	writeMu     sync.Mutex
	writeOffset protocol.ByteCount
	writeErr    error

	// Flow control
	flowController flowcontrol.StreamFlowController

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

func newStream(ctx context.Context, streamID protocol.StreamID, conn *Connection, flowController flowcontrol.StreamFlowController) *Stream {
	s := &Stream{
		streamID:       streamID,
		conn:           conn,
		readBuffer:     new(bytes.Buffer),
		flowController: flowController,
		finalSize:      protocol.MaxByteCount,
		receiveBuffer:  make(map[protocol.ByteCount][]byte),
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.readCond = sync.NewCond(&s.readMu)
	return s
}

// StreamID returns the stream's ID.
func (s *Stream) StreamID() protocol.StreamID {
	return s.streamID
}

// Read reads data from the stream. It blocks until data is available or the stream is closed.
func (s *Stream) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for s.readBuffer.Len() == 0 && s.readErr == nil {
		if s.isFinished && s.bytesRead == s.finalSize {
			log.Printf("[STREAM %d] Read returning EOF. Total bytes read: %d", s.streamID, s.bytesRead)
			return 0, io.EOF
		}
		// log.Printf("[STREAM %d] Read waiting. Buffer len: %d, Bytes read: %d, Final size: %d, Finished: %t", s.streamID, s.readBuffer.Len(), s.bytesRead, s.finalSize, s.isFinished)
		s.readCond.Wait()
		// log.Printf("[STREAM %d] Read woken up.", s.streamID)
	}

	if s.readErr != nil {
		return 0, s.readErr
	}

	n, err = s.readBuffer.Read(p)
	s.bytesRead += protocol.ByteCount(n)
	// log.Printf("[STREAM %d] Read %d bytes. Total bytes read: %d", s.streamID, n, s.bytesRead)
	return n, err
}

// Write writes data to the stream. It may block if flow control prevents sending.
func (s *Stream) Write(p []byte) (n int, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.writeErr != nil {
		return 0, s.writeErr
	}

	const maxDataSize = 1100

	var totalSent int
	for len(p) > 0 {
		chunkSize := maxDataSize
		if len(p) < chunkSize {
			chunkSize = len(p)
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		s.conn.sendStreamData(s.streamID, chunk, false, s.writeOffset)
		s.writeOffset += protocol.ByteCount(len(chunk))
		totalSent += len(chunk)
	}
	return totalSent, nil
}

// Close signals that no more data will be written to the stream.
func (s *Stream) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.conn.sendStreamData(s.streamID, nil, true, s.writeOffset)
	s.writeErr = errors.New("stream closed")
	return nil
}

// handleStreamFrame is called by the connection's receive loop when a STREAM frame arrives.
func (s *Stream) handleStreamFrame(frame *wire.StreamFrame) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if frame.DataLen() > 0 {
		if frame.Offset+frame.DataLen() <= s.readOffset {
			log.Printf("[STREAM %d] Ignoring duplicate frame at offset %d", s.streamID, frame.Offset)
			return
		}
		// log.Printf("[STREAM %d] Buffering frame at offset %d, len %d", s.streamID, frame.Offset, frame.DataLen())
		s.receiveBuffer[frame.Offset] = frame.Data
	}

	if frame.Fin {
		s.isFinished = true
		s.finalSize = frame.Offset + frame.DataLen()
		log.Printf("[STREAM %d] Received FIN. Final size: %d", s.streamID, s.finalSize)
	}

	s.reassemble()
	s.readCond.Broadcast()
}

// reassemble checks the receive buffer for contiguous data and moves it to the read buffer.
func (s *Stream) reassemble() {
	offsets := make([]protocol.ByteCount, 0, len(s.receiveBuffer))
	for offset := range s.receiveBuffer {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	// log.Printf("[STREAM %d] Reassembling. Current read offset: %d. Buffered offsets: %v", s.streamID, s.readOffset, offsets)
	for _, offset := range offsets {
		if offset == s.readOffset {
			data := s.receiveBuffer[offset]
			s.readBuffer.Write(data)
			s.readOffset += protocol.ByteCount(len(data))
			// log.Printf("[STREAM %d] Reassembled frame at offset %d. New read offset: %d", s.streamID, offset, s.readOffset)
			delete(s.receiveBuffer, offset)
		} else if offset < s.readOffset {
			delete(s.receiveBuffer, offset)
		} else {
			log.Printf("[STREAM %d] Gap in stream. Expected offset %d, found %d. Stopping reassembly.", s.streamID, s.readOffset, offset)
			break
		}
	}
}

// cancelRead is called when the connection is closed.
func (s *Stream) cancelRead(err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readErr = err
	s.readCond.Broadcast()
}
