package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ApplicationData struct {
	RecordHeader RecordHeader
	Data         []byte
	Payload      []byte
}

func MakeApplicationData(key, iv, data []byte) ApplicationData {
	clientApplicationData := ApplicationData{}
	clientApplicationData.Data = data

	clientApplicationData.Payload = cryptoHelpers.Encrypt(key, iv, data, 1, 0x17)

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x17
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	recordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(clientApplicationData.Payload)))

	clientApplicationData.RecordHeader = recordHeader

	return clientApplicationData
}

func (applicationData ApplicationData) GetPayload() []byte {
	var payload []byte

	payload = append(payload, applicationData.RecordHeader.Type)
	payload = append(payload, applicationData.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, applicationData.RecordHeader.Length[:]...)
	payload = append(payload, applicationData.Payload...)

	return payload
}

func ParseApplicationData(serverKey, serverIV, answer []byte, seqNum byte) ApplicationData {
	offset := 0
	serverApplicationData := ApplicationData{}

	serverApplicationData.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	serverApplicationData.Payload = answer[offset:]

	serverApplicationData.Data = cryptoHelpers.Decrypt(serverKey, serverIV, serverApplicationData.Payload, seqNum, serverApplicationData.RecordHeader.Type)

	return serverApplicationData
}