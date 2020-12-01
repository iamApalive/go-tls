package model

import (
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type ClientHello struct {
	RecordHeader 			   RecordHeader
	HandshakeHeader            HandshakeHeader
	ClientVersion              [2]byte
	ClientRandom               [32]byte
	SessionID                  [1]byte
	CipherSuitesLength		   [2]byte
	CipherSuites               []byte
	CompressionMethodsLength   [1]byte
	CompressionMethods         []byte
}

func MakeClientHello() ClientHello {
	clientHello := ClientHello{}

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x16
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.0")

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = 0x1

	clientHello.ClientVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	clientHello.ClientRandom = [32]byte{}

	clientHello.SessionID = [1]byte{0x00}

	suitesByteCode := constants.GCipherSuites.GetSuiteByteCodes(constants.GCipherSuites.GetAllSuites())

	clientHello.CipherSuites = suitesByteCode
	clientHello.CipherSuitesLength = helpers.ConvertIntToByteArray(uint16(len(suitesByteCode)))

	clientHello.CompressionMethods = []byte{0x00}
	clientHello.CompressionMethodsLength = [1]byte{0x01}

	handshakeHeader.MessageLength = clientHello.getHandshakeHeaderLength()
	clientHello.HandshakeHeader = handshakeHeader

	recordHeader.Length = clientHello.getRecordLength()
	clientHello.RecordHeader = recordHeader

	return clientHello
}

func (clientHello ClientHello) getHandshakeHeaderLength() [3]byte {
	var length [3]byte
	var k int

	k = len(clientHello.ClientVersion)
	k += len(clientHello.ClientRandom)
	k += len(clientHello.SessionID)
	k += len(clientHello.CipherSuitesLength)
	k += len(clientHello.CipherSuites)
	k += len(clientHello.CompressionMethodsLength)
	k += len(clientHello.CompressionMethods)

	tmp := helpers.ConvertIntToByteArray(uint16(k))
	length[0] = 0x00
	length[1] = tmp[0]
	length[2] = tmp[1]

	return length
}

func (clientHello ClientHello) getRecordLength() [2]byte {
	tmp := int(helpers.ConvertByteArrayToInt(clientHello.HandshakeHeader.MessageLength[1:]))
	tmp += 1
	tmp += len(clientHello.HandshakeHeader.MessageLength)

	return helpers.ConvertIntToByteArray(uint16(tmp))
}

func (clientHello ClientHello) GetClientHelloPayload() []byte {
	var payload []byte

	payload = append(payload, clientHello.RecordHeader.Type)
	payload = append(payload, clientHello.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHello.RecordHeader.Length[:]...)
	payload = append(payload, clientHello.HandshakeHeader.MessageType)
	payload = append(payload, clientHello.HandshakeHeader.MessageLength[:]...)
	payload = append(payload, clientHello.ClientVersion[:]...)
	payload = append(payload, clientHello.ClientRandom[:]...)
	payload = append(payload, clientHello.SessionID[:]...)
	payload = append(payload, clientHello.CipherSuitesLength[:]...)
	payload = append(payload, clientHello.CipherSuites[:]...)
	payload = append(payload, clientHello.CompressionMethodsLength[:]...)
	payload = append(payload, clientHello.CompressionMethods...)

	return payload
}
