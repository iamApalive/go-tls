package model

import (
	"github.com/viorelyo/tlsExperiment/coreUtils"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
)
// TODO refactor this!
type ApplicationData struct {
	RecordHeader RecordHeader
	Data         []byte
	Payload      []byte
}

func MakeApplicationData(clientKey, clientIV, data []byte, additionalData coreUtils.AdditionalData) ApplicationData {
	clientApplicationData := ApplicationData{}
	clientApplicationData.Data = data

	clientApplicationData.Payload = cryptoHelpers.Encrypt(clientKey, clientIV, data, additionalData)

	recordHeader := RecordHeader{}
	recordHeader.Type = additionalData.RecordType
	recordHeader.ProtocolVersion = additionalData.TlsVersion
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

func ParseApplicationData(serverKey, serverIV, answer []byte, serverSeqNumber byte) ApplicationData {
	offset := 0
	serverApplicationData := ApplicationData{}

	serverApplicationData.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	serverApplicationData.Payload = answer[offset:]

	additionalData := coreUtils.MakeAdditionalData(serverSeqNumber, serverApplicationData.RecordHeader.Type, serverApplicationData.RecordHeader.ProtocolVersion)
	serverApplicationData.Data = cryptoHelpers.Decrypt(serverKey, serverIV, serverApplicationData.Payload, additionalData)

	return serverApplicationData
}
