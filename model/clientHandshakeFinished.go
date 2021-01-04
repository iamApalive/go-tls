package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientHandshakeFinished struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	VerifyData      []byte
}

func MakeClientHandshakeFinished(verifyData []byte, tlsVersion [2]byte) ClientHandshakeFinished {
	clientHandshakeFinished := ClientHandshakeFinished{}

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = tlsVersion
	clientHandshakeFinished.RecordHeader = recordHeader

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientFinished
	// TODO check that the length is not hardcoded
	handshakeHeader.MessageLength = [3]byte {0x00, 0x00, 0x0c}	// length of verifyData = 12
	clientHandshakeFinished.HandshakeHeader = handshakeHeader

	clientHandshakeFinished.VerifyData = verifyData

	return clientHandshakeFinished
}

func (clientHandshakeFinished ClientHandshakeFinished) GetClientHandshakeFinishedPlaintextPayload() []byte {
	var plaintext []byte

	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageType)
	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageLength[:]...)
	plaintext = append(plaintext, clientHandshakeFinished.VerifyData...)

	return plaintext
}

func (clientHandshakeFinished ClientHandshakeFinished) GetClientHandshakeFinishedPayload(encryptedContent []byte) []byte {
	clientHandshakeFinished.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(encryptedContent)))

	var payload []byte

	payload = append(payload, clientHandshakeFinished.RecordHeader.Type)
	payload = append(payload, clientHandshakeFinished.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHandshakeFinished.RecordHeader.Length[:]...)
	payload = append(payload, encryptedContent...)

	return payload
}
