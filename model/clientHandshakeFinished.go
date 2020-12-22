package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientHandshakeFinished struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	EncryptionIV    []byte
	VerifyData      []byte
}

func MakeClientHandshakeFinished(encryptionIV []byte, verifyData []byte) ClientHandshakeFinished {
	clientHandshakeFinished := ClientHandshakeFinished{}

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x16
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	//recordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(encryptionIV) + len(verifyData)))
	recordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(verifyData) + 4))

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientFinished
	handshakeHeader.MessageLength = [3]byte {0x00, 0x00, 0x0c}	// length of verifyData = 12


	clientHandshakeFinished.RecordHeader = recordHeader
	//clientHandshakeFinished.EncryptionIV = encryptionIV
	clientHandshakeFinished.VerifyData = verifyData

	return clientHandshakeFinished
}

func (clientHandshakeFinished ClientHandshakeFinished) GetClientHandshakeFinishedPayload() []byte {
	var payload []byte

	payload = append(payload, clientHandshakeFinished.RecordHeader.Type)
	payload = append(payload, clientHandshakeFinished.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHandshakeFinished.RecordHeader.Length[:]...)
	//payload = append(payload, clientHandshakeFinished.EncryptionIV...)
	payload = append(payload, clientHandshakeFinished.VerifyData...)

	return payload
}
