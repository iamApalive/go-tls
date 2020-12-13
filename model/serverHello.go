package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)


type ServerHello struct {
	RecordHeader               RecordHeader
	HandshakeHeader            HandshakeHeader
	ServerVersion              [2]byte
	ServerRandom               [32]byte
	SessionIDLength            [1]byte
	SessionID                  []byte
	CipherSuite                [2]byte
	CompressionMethod          [1]byte
}

func ParseServerHello(answer []byte) (ServerHello, []byte, error) {
	//println("Parsing Server Hello")
	offset := 0
	serverHello := ServerHello{}

	serverHello.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	serverHello.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverHello.HandshakeHeader.MessageType != constants.HandshakeServerHello {
		return serverHello, answer, helpers.ServerHelloMissingError()
	}

	copy(serverHello.ServerVersion[:], answer[offset:offset+2])
	copy(serverHello.ServerRandom[:], answer[offset+2:offset+34])
	copy(serverHello.SessionIDLength[:], answer[offset+34:offset+35])

	sessionIDLenghtInt := int(serverHello.SessionIDLength[0])
	if sessionIDLenghtInt > 0 {
		serverHello.SessionID = answer[offset+35 : offset+sessionIDLenghtInt+35]
		offset += sessionIDLenghtInt
		//println("copy sessionIDLenght copied len:", serverHello.SessionIDLenghtInt)
	}

	copy(serverHello.CipherSuite[:], answer[offset+35:offset+37])
	copy(serverHello.CompressionMethod[:], answer[offset+37:offset+38])
	offset += 38

	serverHelloLength := int(helpers.ConvertByteArrayToUInt16(serverHello.RecordHeader.Length))
	if serverHelloLength != (offset - 5) {		// 5 is the length of RecordHeader
		return serverHello, answer, helpers.ServerHelloParsingError()
	}

	return serverHello, answer[offset:], nil
}

func (serverHello ServerHello) String() string {
	out := fmt.Sprintf("Server Hello\n")
	out += fmt.Sprint(serverHello.RecordHeader)
	out += fmt.Sprint(serverHello.HandshakeHeader)
	out += fmt.Sprintf("  Server Version.....: %6x\n", serverHello.ServerVersion)
	out += fmt.Sprintf("  Server Random......: %6x\n", serverHello.ServerRandom)
	out += fmt.Sprintf("  Session ID length..: %6x\n", serverHello.SessionIDLength)
	out += fmt.Sprintf("  Session ID.........: %6x\n", serverHello.SessionID)
	out += fmt.Sprintf("  CipherSuite........: %6x - %s\n", serverHello.CipherSuite, constants.GCipherSuites.GetSuiteForByteCode(serverHello.CipherSuite))
	out += fmt.Sprintf("  CompressionMethod..: %6x\n", serverHello.CompressionMethod)
	return out
}

// TODO make parsing functions methods of ServerHello struct