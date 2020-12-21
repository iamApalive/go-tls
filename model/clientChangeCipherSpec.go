package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientChangeCipherSpec struct {
	RecordHeader RecordHeader
	Payload      byte
}

func MakeClientChangeCipherSpec() ClientChangeCipherSpec {
	clientChangeCipherSpec := ClientChangeCipherSpec{}

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x14
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	recordHeader.Length = helpers.ConvertIntToByteArray(uint16(1))

	clientChangeCipherSpec.RecordHeader = recordHeader
	clientChangeCipherSpec.Payload = 0x01

	return clientChangeCipherSpec
}

func (clientChangeCipherSpec ClientChangeCipherSpec) GetClientChangeCipherSpecPayload() []byte {
	var payload []byte

	payload = append(payload, clientChangeCipherSpec.RecordHeader.Type)
	payload = append(payload, clientChangeCipherSpec.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientChangeCipherSpec.RecordHeader.Length[:]...)
	payload = append(payload, clientChangeCipherSpec.Payload)

	return payload
}
