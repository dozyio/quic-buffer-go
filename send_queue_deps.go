package main

import (
	"errors"
	"net"
	"syscall"
)

// sendConn is the interface for the underlying network connection.
// It's a subset of the LowerLayerTransport to be used by the sendQueue.
type sendConn interface {
	Write(p []byte) error
	WriteTo(p []byte, addr net.Addr) (int, error)
	Close() error
}

// oobCapablePacketConn is an interface that our transport needs to satisfy
// to work with the sendQueue's Write method.
type oobCapablePacketConn interface {
	Write(p []byte) error
	WriteTo(p []byte, addr net.Addr) (int, error)
	ReadPacket() ([]byte, error)
	Close() error
}

// Make sure our inMemoryTransport satisfies the necessary interfaces.
var (
	_ oobCapablePacketConn = &inMemoryTransport{}
	_ sendConn             = &inMemoryTransport{}
)

// isSendMsgSizeErr checks for the specific "message too long" error.
// This is a simplified check for demonstration. quic-go has a more
// robust, OS-specific implementation.
func isSendMsgSizeErr(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}
