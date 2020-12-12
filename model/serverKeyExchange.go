package model

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type Signature struct {
	Algorithm [2]byte
	Length    [2]byte
	Content   []byte
}

func ParseSignature(answer []byte) (Signature, []byte) {
	var offset uint32
	offset = 0

	signature := Signature{}

	copy(signature.Algorithm[:], answer[offset:offset+2])
	offset += 2

	copy(signature.Length[:], answer[offset:offset+2])
	offset += 2

	tmpLength := uint32(helpers.ConvertByteArrayToUInt16(signature.Length))
	signature.Content = answer[offset:offset+tmpLength]
	offset += tmpLength

	return signature, answer[offset:]
}

func (signature Signature) String() string {
	out := fmt.Sprintf("Signature\n")
	out += fmt.Sprintf("  Algorithm.....: %6x\n", signature.Algorithm)
	out += fmt.Sprintf("  Length........: %6x\n", signature.Length)
	out += fmt.Sprintf("  Signature.....: %6x\n", signature.Content)
	return out
}

type ServerKeyExchange struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	Curve           byte
	CurveID         [2]byte
	PublicKeyLength byte
	PublicKey       []byte
	Signature       Signature
}

func (serverKeyExchange ServerKeyExchange) String() string {
	out := fmt.Sprintf("Server Key Exchange\n")
	out += fmt.Sprint(serverKeyExchange.RecordHeader)
	out += fmt.Sprint(serverKeyExchange.HandshakeHeader)
	out += fmt.Sprintf("  Curve Type.........: %6x\n", serverKeyExchange.Curve)
	out += fmt.Sprintf("  Curve..............: %6x\n", serverKeyExchange.CurveID)
	out += fmt.Sprintf("  Public Key length..: %6x\n", serverKeyExchange.PublicKeyLength)
	out += fmt.Sprintf("  Public Key.........: %6x\n", serverKeyExchange.PublicKey)
	out += fmt.Sprint(serverKeyExchange.Signature)
	return out
}

func ParseServerKeyExchange(answer []byte) (ServerKeyExchange, []byte, error) {
	var offset uint32
	offset = 0
	serverKeyExchange := ServerKeyExchange{}
	serverKeyExchange.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverKeyExchange.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	// TODO safety check for record header length + handshake type
	// TODO define constant for 0xc
	if serverKeyExchange.HandshakeHeader.MessageType != 0xc {
		fmt.Println(serverKeyExchange.RecordHeader)
		fmt.Println(serverKeyExchange.HandshakeHeader)
		log.Warn("No server key exchange")
		return serverKeyExchange, answer, helpers.ServerKeyExchangeParsingError()
	}
	//fmt.Println(answer[offset])

	serverKeyExchange.Curve = answer[offset]
	offset += 1

	copy(serverKeyExchange.CurveID[:], answer[offset:offset+2])
	offset += 2

	serverKeyExchange.PublicKeyLength = answer[offset]
	offset += 1

	tmpLength := uint32(serverKeyExchange.PublicKeyLength)
	serverKeyExchange.PublicKey = answer[offset:offset+tmpLength]
	offset += tmpLength

	serverKeyExchange.Signature, answer = ParseSignature(answer[offset:])

	return serverKeyExchange, answer, nil
}
