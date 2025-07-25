package quicbuffer

import (
	"sync"

	"github.com/dozyio/quic-buffer-go/internal/ackhandler"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
	"github.com/dozyio/quic-buffer-go/internal/wire"
)

type retransmissionQueue struct {
	mu      sync.Mutex
	appData []wire.Frame
	conn    *Connection
}

func newRetransmissionQueue(conn *Connection) *retransmissionQueue {
	return &retransmissionQueue{
		conn: conn,
	}
}

func (q *retransmissionQueue) Add(f wire.Frame) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.appData = append(q.appData, f)
}

func (q *retransmissionQueue) HasData() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.appData) > 0
}

func (q *retransmissionQueue) GetFrame() wire.Frame {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.appData) == 0 {
		return nil
	}
	f := q.appData[0]
	q.appData = q.appData[1:]
	return f
}

func (q *retransmissionQueue) FrameHandler(encLevel protocol.EncryptionLevel) ackhandler.FrameHandler {
	return (*retransmissionQueueAckHandler)(q)
}

type retransmissionQueueAckHandler retransmissionQueue

func (q *retransmissionQueueAckHandler) OnAcked(wire.Frame) {}

func (q *retransmissionQueueAckHandler) OnLost(f wire.Frame) {
	(*retransmissionQueue)(q).Add(f)
}
