package main

import (
	"github.com/dozyio/quic-buffer-go/handshake"
	"github.com/dozyio/quic-buffer-go/protocol"
)

// nullAEAD is a dummy struct that implements the Sealer and Opener interfaces
// from quic-go's handshake package. It passes data through without any
// encryption or authentication. This is the "dummy crypto layer".
type nullAEAD struct{}

var (
	_ handshake.Sealer = &nullAEAD{}
	_ handshake.Opener = &nullAEAD{}
)

// Seal does nothing but append the plaintext to the destination and return it.
func (n *nullAEAD) Seal(dst, plaintext []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return append(dst, plaintext...)
}

// Open does nothing but append the ciphertext to the destination and return it.
func (n *nullAEAD) Open(dst, ciphertext []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

// Overhead returns 0 because we add no authentication tags or other overhead.
func (n *nullAEAD) Overhead() int {
	return 0
}

func (n *nullAEAD) KeyPhase() protocol.KeyPhaseBit {
	return protocol.KeyPhaseZero
}
