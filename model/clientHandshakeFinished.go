package model

import "github.com/viorelyo/tlsExperiment/constants"

type ClientHandshakeFinished struct {
	RecordHeader RecordHeader
	EncryptionIV []byte
}

func MakeClientHandshakeFinished(preMessage []byte) ClientHandshakeFinished {
	clientHandshakeFinished := ClientHandshakeFinished{}

	recordHeader := RecordHeader{}
	recordHeader.Type = 0x16
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")



	return clientHandshakeFinished
}


