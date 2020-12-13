package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ServerHelloDone struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
}

func (serverHelloDone ServerHelloDone) String() string {
	out := fmt.Sprintf("Server Hello Done\n")
	out += fmt.Sprint(serverHelloDone.RecordHeader)
	out += fmt.Sprint(serverHelloDone.HandshakeHeader)
	return out
}

func ParseServerHelloDone(answer []byte) (ServerHelloDone, []byte, error) {
	var offset uint32
	offset = 0
	serverHelloDone := ServerHelloDone{}
	serverHelloDone.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverHelloDone.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverHelloDone.HandshakeHeader.MessageType != constants.HandshakeServerHelloDone {
		return serverHelloDone, answer, helpers.ServerHelloDoneMissingError()
	}

	return serverHelloDone, answer[offset:], nil
}
