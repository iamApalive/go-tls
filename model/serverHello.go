package model

import "fmt"

type ExtensionRenegotiationInfo struct {
	Info    [2]byte
	Length  [2]byte
	Payload [1]byte
}

type ServerHello struct {
	RecordHeader               RecordHeader
	HandshakeHeader            HandshakeHeader
	ServerVersion              [2]byte
	ServerRandom               [32]byte
	SessionIDLenght            [1]byte
	SessionIDLenghtInt         int
	SessionID                  []byte
	CipherSuite                [2]byte // https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
	CompressionMethod          [1]byte
	ExtensionLength            [2]byte
	ExtensionRenegotiationInfo ExtensionRenegotiationInfo
}

func (serverHello ServerHello) String() string {
	out := fmt.Sprintf("Server Hello\n")
	out += fmt.Sprint(serverHello.RecordHeader)
	out += fmt.Sprint(serverHello.HandshakeHeader)
	out += fmt.Sprintf("  Server Version.....: %6x\n", serverHello.ServerVersion)
	out += fmt.Sprintf("  Server Random......: %6x\n", serverHello.ServerRandom)
	out += fmt.Sprintf("  Session ID length..: %6x\n", serverHello.SessionIDLenght)
	out += fmt.Sprintf("  Session ID lengthI.: %6d\n", serverHello.SessionIDLenghtInt)
	out += fmt.Sprintf("  Session ID.........: %6x\n", serverHello.SessionID)
	out += fmt.Sprintf("  CipherSuite........: %6x\n", serverHello.CipherSuite)
	out += fmt.Sprintf("  CompressionMethod..: %6x\n", serverHello.CompressionMethod)
	out += fmt.Sprintf("  ExtensionLength....: %6x\n", serverHello.ExtensionLength)
	//out += fmt.Sprintf("s%", serverHello.extensionRenegotiationInfo)
	out += fmt.Sprint(serverHello.ExtensionRenegotiationInfo)
	return out
}