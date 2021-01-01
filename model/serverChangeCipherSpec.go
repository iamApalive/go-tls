package model

import (
	"fmt"
)

type ServerChangeCipherSpec struct {
	RecordHeader RecordHeader
	Payload      byte
}

func ParseServerChangeCipherSpec(answer []byte) (ServerChangeCipherSpec, []byte) {
	var offset uint32
	offset = 0
	serverChangeCipherSpec := ServerChangeCipherSpec{}
	serverChangeCipherSpec.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverChangeCipherSpec.Payload = answer[offset]
	offset += 1

	return serverChangeCipherSpec, answer
}

func (serverChangeCipherSpec ServerChangeCipherSpec) String() string {
	out := fmt.Sprintf("Server Change Cipher Spec\n")
	out += fmt.Sprint(serverChangeCipherSpec.RecordHeader)
	out += fmt.Sprintf("  Payload.........: %6x\n", serverChangeCipherSpec.Payload)
	return out
}