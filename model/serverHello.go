package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
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