package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

// Stream is the application-facing object for a single bidirectional stream.
// It buffers read and write data and interacts with the connection's flow controller.
type Stream struct {
	streamID protocol.StreamID
	conn     *Connection // The parent connection

	// Read-side
	readMu     sync.Mutex
	readBuffer *bytes.Buffer
	readCond   *sync.Cond // Notifies when new data arrives
	isFinished bool       // True if a FIN has been received
	readErr    error

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

	for {
		if s.readBuffer.Len() > 0 {
			return s.readBuffer.Read(p)
		}
		if s.readErr != nil {
			return 0, s.readErr
		}
		if s.isFinished {
			return 0, io.EOF
		}
		s.readCond.Wait()
	}
}

// Write writes data to the stream. It may block if flow control prevents sending.
func (s *Stream) Write(p []byte) (n int, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.writeErr != nil {
		return 0, s.writeErr
	}

	const maxDataSize = 1100 // A conservative chunk size to leave room for packet headers.

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
// This will cause a STREAM frame with the FIN bit set to be sent.
func (s *Stream) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.conn.sendStreamData(s.streamID, nil, true, s.writeOffset) // fin = true
	s.writeErr = errors.New("stream closed")
	return nil
}

// handleStreamFrame is called by the connection's receive loop when a STREAM frame arrives.
func (s *Stream) handleStreamFrame(frame *wire.StreamFrame) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if frame.DataLen() > 0 {
		// A real implementation would check flow control limits here.
		s.readBuffer.Write(frame.Data)
	}
	if frame.Fin {
		s.isFinished = true
	}

	// Signal any waiting Read() calls that data is available or the stream is finished.
	s.readCond.Broadcast()
}

// cancelRead is called when the connection is closed.
func (s *Stream) cancelRead(err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readErr = err
	s.readCond.Broadcast()
}
