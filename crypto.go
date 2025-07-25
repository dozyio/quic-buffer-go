package quicbuffer

import (
	"time"

	"github.com/dozyio/quic-buffer-go/internal/handshake"
	"github.com/dozyio/quic-buffer-go/internal/protocol"
)

// nullLongHeaderAEAD is a dummy AEAD for Initial and Handshake packets.
type nullLongHeaderAEAD struct{}

var (
	_ handshake.LongHeaderSealer = &nullLongHeaderAEAD{}
	_ handshake.LongHeaderOpener = &nullLongHeaderAEAD{}
)

func (n *nullLongHeaderAEAD) Seal(dst, plaintext []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return append(dst, plaintext...)
}

func (n *nullLongHeaderAEAD) Open(dst, ciphertext []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func (n *nullLongHeaderAEAD) Overhead() int { return 0 }

func (n *nullLongHeaderAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}
func (n *nullLongHeaderAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}
func (n *nullLongHeaderAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return wirePN
}

// nullShortHeaderAEAD is a dummy AEAD for 1-RTT packets.
type nullShortHeaderAEAD struct{}

var (
	_ handshake.ShortHeaderSealer = &nullShortHeaderAEAD{}
	_ handshake.ShortHeaderOpener = &nullShortHeaderAEAD{}
)

func (n *nullShortHeaderAEAD) Seal(dst, plaintext []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return append(dst, plaintext...)
}

func (n *nullShortHeaderAEAD) Open(dst, ciphertext []byte, rcvTime time.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func (n *nullShortHeaderAEAD) Overhead() int { return 0 }

func (n *nullShortHeaderAEAD) KeyPhase() protocol.KeyPhaseBit { return protocol.KeyPhaseZero }

func (n *nullShortHeaderAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}
func (n *nullShortHeaderAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {}
func (n *nullShortHeaderAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return wirePN
}
