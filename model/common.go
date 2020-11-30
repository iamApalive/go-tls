package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
)


type RecordHeader struct {
	Ttype            byte
	Protocol_version [2]byte
	Footer           [2]byte
	FooterInt        uint16
}

func (recordHeader RecordHeader) String() string {
	out := fmt.Sprintf("  Record Header\n")
	out += fmt.Sprintf("    ttype............:     %02x\n", recordHeader.Ttype)
	out += fmt.Sprintf("    protocol Version.: %6x - %s\n", recordHeader.Protocol_version, constants.GTlsVersions.GetVersionForByteCode(recordHeader.Protocol_version))
	out += fmt.Sprintf("    footer...........: %6x\n", recordHeader.Footer)
	out += fmt.Sprintf("    footerInt........: %6x\n", recordHeader.FooterInt)
	return out
}

type HandshakeHeader struct {
	Message_type byte
	Footer       [3]byte
	FooterInt    uint32
}

func (handshakeHeader HandshakeHeader) String() string {
	out := fmt.Sprintf("  Handshake Header\n")
	out += fmt.Sprintf("    message type.....:     %02x\n", handshakeHeader.Message_type)
	out += fmt.Sprintf("    footer...........: %6x\n", handshakeHeader.Footer)
	out += fmt.Sprintf("    footerInt........: %6d\n", handshakeHeader.FooterInt)
	return out
}