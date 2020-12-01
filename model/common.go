package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
)


type RecordHeader struct {
	Type            byte
	ProtocolVersion [2]byte
	Length          [2]byte
}

func (recordHeader RecordHeader) String() string {
	out := fmt.Sprintf("  Record Header\n")
	out += fmt.Sprintf("    ttype............:     %02x\n", recordHeader.Type)
	out += fmt.Sprintf("    protocol Version.: %6x - %s\n", recordHeader.ProtocolVersion, constants.GTlsVersions.GetVersionForByteCode(recordHeader.ProtocolVersion))
	out += fmt.Sprintf("    footer...........: %6x\n", recordHeader.Length)
	return out
}

type HandshakeHeader struct {
	MessageType   byte
	MessageLength [3]byte
}

func (handshakeHeader HandshakeHeader) String() string {
	out := fmt.Sprintf("  Handshake Header\n")
	out += fmt.Sprintf("    message type.....:     %02x\n", handshakeHeader.MessageType)
	out += fmt.Sprintf("    footer...........: %6x\n", handshakeHeader.MessageLength)
	return out
}