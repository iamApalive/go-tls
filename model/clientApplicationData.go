package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientApplicationData struct {
	RecordHeader RecordHeader
	Data         []byte
	Payload      []byte
}

func MakeClientApplicationData(key, iv, data []byte) ClientApplicationData {
	clientApplicationData := ClientApplicationData{}
	clientApplicationData.Data = data

	clientApplicationData.Payload = cryptoHelpers.Encrypt(key, iv, data, 1, 0x17)

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x17
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	recordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(clientApplicationData.Payload)))

	clientApplicationData.RecordHeader = recordHeader

	return clientApplicationData
}

func (clientApplicationData ClientApplicationData) GetPayload() []byte {
	var payload []byte

	payload = append(payload, clientApplicationData.RecordHeader.Type)
	payload = append(payload, clientApplicationData.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientApplicationData.RecordHeader.Length[:]...)
	payload = append(payload, clientApplicationData.Payload...)

	return payload
}