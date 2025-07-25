package quicbuffer

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/dozyio/quic-buffer-go/internal/flowcontrol"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

type Stream struct {
	id          protocol.StreamID
	conn        *Connection
	fc          flowcontrol.StreamFlowController
	ctx         context.Context
	ctxCancel   context.CancelFunc
	writeOffset protocol.ByteCount

	mu          sync.Mutex
	sorter      *frameSorter
	finReceived bool
	finalOffset protocol.ByteCount
	readOffset  protocol.ByteCount
	readBuffer  []byte
	readReady   chan struct{}
	readErr     error
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

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if s.readErr != nil {
			return 0, s.readErr
		}
		if len(s.readBuffer) > 0 {
			n := copy(p, s.readBuffer)
			s.readBuffer = s.readBuffer[n:]
			s.readOffset += protocol.ByteCount(n)
			return n, nil
		}
		if s.finReceived && s.readOffset >= s.finalOffset {
			return 0, io.EOF
		}

		_, data, _ := s.sorter.Pop()
		if len(data) == 0 {
			s.mu.Unlock()
			select {
			case <-s.ctx.Done():
				s.mu.Lock()
				return 0, s.ctx.Err()
			case <-s.readReady:
				s.mu.Lock()
				continue
			}
		}
		s.readBuffer = data
	}
}

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
		const maxFrameDataSize = InitialPacketSize
		end := min(bytesSent+maxFrameDataSize, totalLen)
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
