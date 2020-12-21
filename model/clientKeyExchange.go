package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientKeyExchange struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	PublicKeyLength byte
	PublicKey       []byte
}

func MakeClientKeyExchange() ClientKeyExchange {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privateKey.PublicKey
	publicKeyArr := elliptic.Marshal(publicKey, publicKey.X, publicKey.Y)
	log.Info(publicKeyArr)

	clientKeyExchange := ClientKeyExchange{}
	clientKeyExchange.PublicKeyLength = byte(len(publicKeyArr))
	clientKeyExchange.PublicKey = publicKeyArr

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x16
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientKeyExchange
	handshakeHeader.MessageLength = clientKeyExchange.getHandshakeHeaderLength()
	clientKeyExchange.HandshakeHeader = handshakeHeader

	recordHeader.Length = clientKeyExchange.getRecordLength()
	clientKeyExchange.RecordHeader = recordHeader

	return clientKeyExchange
}

func (clientKeyExchange ClientKeyExchange) getHandshakeHeaderLength() [3]byte {
	var length [3]byte

	k := uint16(clientKeyExchange.PublicKeyLength)
	k += 1 	// size of PublicKeyLength

	tmp := helpers.ConvertIntToByteArray(k)
	length[0] = 0x00
	length[1] = tmp[0]
	length[2] = tmp[1]

	return length
}

func (clientKeyExchange ClientKeyExchange) getRecordLength() [2]byte {
	tmp := int(helpers.Convert3ByteArrayToUInt32(clientKeyExchange.HandshakeHeader.MessageLength))
	tmp += 1 	// size of MessageType
	tmp += len(clientKeyExchange.HandshakeHeader.MessageLength)

	return helpers.ConvertIntToByteArray(uint16(tmp))
}

func (clientKeyExchange ClientKeyExchange) GetClientKeyExchangePayload() []byte {
	var payload []byte

	payload = append(payload, clientKeyExchange.RecordHeader.Type)
	payload = append(payload, clientKeyExchange.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientKeyExchange.RecordHeader.Length[:]...)
	payload = append(payload, clientKeyExchange.HandshakeHeader.MessageType)
	payload = append(payload, clientKeyExchange.HandshakeHeader.MessageLength[:]...)
	payload = append(payload, clientKeyExchange.PublicKeyLength)
	payload = append(payload, clientKeyExchange.PublicKey...)

	return payload
}