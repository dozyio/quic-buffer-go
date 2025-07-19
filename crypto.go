package main

import (
	"time"

	"github.com/dozyio/quic-buffer-go/handshake"
	"github.com/dozyio/quic-buffer-go/protocol"
)

// nullAEAD is a dummy struct that implements the Sealer and Opener interfaces
// from quic-go's handshake package. It passes data through without any
// encryption or authentication. This is the "dummy crypto layer".
type nullAEAD struct{}

var (
	_ handshake.ShortHeaderSealer = &nullAEAD{}
	_ handshake.ShortHeaderOpener = &nullAEAD{}
)

// Seal does nothing but append the plaintext to the destination and return it.
func (n *nullAEAD) Seal(dst, plaintext []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return append(dst, plaintext...)
}

// Open for ShortHeaderOpener
func (n *nullAEAD) Open(dst, src []byte, rcvTime time.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	return append(dst, src...), nil
}

// Overhead returns 0 because we add no authentication tags or other overhead.
func (n *nullAEAD) Overhead() int {
	return 0
}

func (n *nullAEAD) KeyPhase() protocol.KeyPhaseBit {
	return protocol.KeyPhaseZero
}

func (n *nullAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}
func (n *nullAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}

func (n *nullAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	// This is a simplified implementation for the dummy AEAD.
	// A real implementation would use the largest acknowledged packet number.
	return wirePN
}
