package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/coreUtils"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientHandshakeFinished struct {
	RecordHeader     RecordHeader
	HandshakeHeader  HandshakeHeader
	VerifyData       []byte
	EncryptedContent []byte
}

func MakeClientHandshakeFinished(clientKey, clientIV, verifyData []byte, tlsVersion [2]byte, seqNum byte) (ClientHandshakeFinished, error) {
	clientHandshakeFinished := ClientHandshakeFinished{}

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = tlsVersion
	clientHandshakeFinished.RecordHeader = recordHeader

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientFinished
	// TODO check that the length is not hardcoded
	handshakeHeader.MessageLength = [3]byte{0x00, 0x00, 0x0c} // length of verifyData = 12
	clientHandshakeFinished.HandshakeHeader = handshakeHeader

	clientHandshakeFinished.VerifyData = verifyData

	var plaintext []byte
	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageType)
	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageLength[:]...)
	plaintext = append(plaintext, clientHandshakeFinished.VerifyData...)

	additionalData := coreUtils.MakeAdditionalData(seqNum, clientHandshakeFinished.RecordHeader.Type, tlsVersion)
	encryptedContent, err := cryptoHelpers.Encrypt(clientKey, clientIV, plaintext, additionalData)
	if err != nil {
		return clientHandshakeFinished, err
	}
	clientHandshakeFinished.EncryptedContent = encryptedContent

	clientHandshakeFinished.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(encryptedContent)))

	return clientHandshakeFinished, nil
}

func (clientHandshakeFinished ClientHandshakeFinished) GetClientHandshakeFinishedPayload() []byte {
	var payload []byte

	payload = append(payload, clientHandshakeFinished.RecordHeader.Type)
	payload = append(payload, clientHandshakeFinished.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHandshakeFinished.RecordHeader.Length[:]...)
	payload = append(payload, clientHandshakeFinished.EncryptedContent...)

	return payload
}
