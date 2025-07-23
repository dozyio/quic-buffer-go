package main

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

// Stream is a QUIC-like stream implementation.
type Stream struct {
	id          protocol.StreamID
	conn        *Connection
	fc          flowcontrol.StreamFlowController
	ctx         context.Context
	ctxCancel   context.CancelFunc
	writeOffset protocol.ByteCount

	mu sync.Mutex
	// The sorter is only for data reassembly.
	sorter *frameSorter
	// FIN state is managed separately.
	finReceived bool
	finalOffset protocol.ByteCount
	readOffset  protocol.ByteCount
	// New buffer to handle partial reads correctly.
	readBuffer []byte

	readReady chan struct{}
	readErr   error
}

func newStream(ctx context.Context, id protocol.StreamID, conn *Connection, fc flowcontrol.StreamFlowController) *Stream {
	readCtx, cancel := context.WithCancel(ctx)
	return &Stream{
		id:        id,
		conn:      conn,
		fc:        fc,
		ctx:       readCtx,
		ctxCancel: cancel,
		sorter:    newFrameSorter(),
		readReady: make(chan struct{}, 1),
	}
}

func (s *Stream) cancel(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.mu.Unlock()
	s.ctxCancel()
}

// ** THIS IS THE FINAL, CORRECTED Read FUNCTION **
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		// First, check if there's an error on the stream.
		if s.readErr != nil {
			return 0, s.readErr
		}
		// If we have data in our internal buffer, serve it first.
		if len(s.readBuffer) > 0 {
			n := copy(p, s.readBuffer)
			s.readBuffer = s.readBuffer[n:]
			s.readOffset += protocol.ByteCount(n)
			return n, nil
		}
		// If the buffer is empty, check if we've reached the end of the stream.
		if s.finReceived && s.readOffset >= s.finalOffset {
			return 0, io.EOF
		}

		// Our buffer is empty and the stream is not finished, so try to get more data.
		_, data, _ := s.sorter.Pop()

		if len(data) == 0 {
			// No contiguous data is available from the sorter, so there's a gap. We must wait.
			s.mu.Unlock()
			select {
			case <-s.ctx.Done():
				s.mu.Lock()
				return 0, s.ctx.Err()
			case <-s.readReady:
				s.mu.Lock()
				// Loop again to try popping from the sorter.
				continue
			}
		}

		// We successfully popped a new chunk of data. Put it in our buffer and loop
		// to serve it in the next iteration.
		s.readBuffer = data
	}
}

// ... (handleStreamFrame, Write, and Close are correct from the previous step) ...
func (s *Stream) handleStreamFrame(f *wire.StreamFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readErr != nil {
		return
	}
	if s.finReceived && f.Offset+protocol.ByteCount(len(f.Data)) > s.finalOffset {
		s.readErr = errors.New("protocol violation: received data after FIN")
		return
	}
	if f.Fin {
		s.finReceived = true
		s.finalOffset = f.Offset + protocol.ByteCount(len(f.Data))
	}
	if len(f.Data) > 0 {
		if err := s.sorter.Push(f.Data, f.Offset, nil); err != nil {
			log.Printf("[STREAM %d] Error pushing data to sorter: %v", s.id, err)
			s.readErr = err
		}
	}
	select {
	case s.readReady <- struct{}{}:
	default:
	}
}

func (s *Stream) Write(p []byte) (n int, err error) {
	totalLen := len(p)
	bytesSent := 0
	for bytesSent < totalLen {
		const maxFrameDataSize = 1200
		end := bytesSent + maxFrameDataSize
		if end > totalLen {
			end = totalLen
		}
		chunk := p[bytesSent:end]
		s.conn.sendStreamData(s.id, chunk, false, s.writeOffset)
		s.writeOffset += protocol.ByteCount(len(chunk))
		bytesSent += len(chunk)
	}
	return totalLen, nil
}

func (s *Stream) Close() error {
	s.conn.sendStreamData(s.id, nil, true, s.writeOffset)
	return nil
}
