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

func ParseRecordHeader(answer []byte) RecordHeader {
	recordHeader := RecordHeader{}
	recordHeader.Type = answer[0]
	copy(recordHeader.ProtocolVersion[:], answer[1:3])
	copy(recordHeader.Length[:], answer[3:5])

	return recordHeader
}

func (recordHeader RecordHeader) String() string {
	out := fmt.Sprintf("  Record Header\n")
	out += fmt.Sprintf("    Type............:     %02x\n", recordHeader.Type)
	out += fmt.Sprintf("    ProtocolVersion.: %6x - %s\n", recordHeader.ProtocolVersion, constants.GTlsVersions.GetVersionForByteCode(recordHeader.ProtocolVersion))
	out += fmt.Sprintf("    Len.............: %6x\n", recordHeader.Length)
	return out
}

type HandshakeHeader struct {
	MessageType   byte
	MessageLength [3]byte
}

func ParseHandshakeHeader(answer []byte) HandshakeHeader {
	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = answer[0]
	copy(handshakeHeader.MessageLength[:], answer[1:4])

	return handshakeHeader
}

func (handshakeHeader HandshakeHeader) String() string {
	out := fmt.Sprintf("  Handshake Header\n")
	out += fmt.Sprintf("    MessageType.....:     %02x\n", handshakeHeader.MessageType)
	out += fmt.Sprintf("    MessageLen......: %6x\n", handshakeHeader.MessageLength)
	return out
}