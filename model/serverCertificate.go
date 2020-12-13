package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
)

// TODO maybe deserialize Certificate Info
type Certificate struct {
	Length  [3]byte
	Content []byte
}

func (certificate Certificate) String() string {
	out := fmt.Sprintf("  Certificate\n")
	out += fmt.Sprintf("    Certificate Length.: %x\n", certificate.Length)
	out += fmt.Sprintf("    Certificate........: %x\n", certificate.Content)
	return out
}

type ServerCertificate struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	CertificateLength [3]byte
	Certificates      []Certificate
}

func ParseServerCertificate(answer []byte) (ServerCertificate, []byte, error) {
	var offset uint32
	offset = 0
	serverCertificate := ServerCertificate{}
	serverCertificate.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverCertificate.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverCertificate.HandshakeHeader.MessageType != constants.HandshakeServerCertificate {
		return serverCertificate, answer, helpers.ServerCertificateMissingError()
	}

	copy(serverCertificate.CertificateLength[:], answer[offset:offset+3])
	totalCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(serverCertificate.CertificateLength)
	offset += 3

	// Parsing list of certificates
	var readCertificateLength uint32
	readCertificateLength = 0
	for readCertificateLength < totalCertificateLengthInt {
		currentCertificate := Certificate{}
		copy(currentCertificate.Length[:], answer[offset:offset+3])
		offset += 3

		crtCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(currentCertificate.Length)

		currentCertificate.Content = answer[offset:offset+crtCertificateLengthInt]
		offset += crtCertificateLengthInt

		serverCertificate.Certificates = append(serverCertificate.Certificates, currentCertificate)
		readCertificateLength += crtCertificateLengthInt + 3 	// 3 - size of Length
	}

	return serverCertificate, answer, nil
}

func (serverCertificate ServerCertificate) String() string {
	out := fmt.Sprintf("Server Certificate\n")
	out += fmt.Sprint(serverCertificate.RecordHeader)
	out += fmt.Sprint(serverCertificate.HandshakeHeader)
	out += fmt.Sprintf("  Certificate Lenght.: %x\n", serverCertificate.CertificateLength)
	out += fmt.Sprintf("Certificates:\n")

	for _, c := range serverCertificate.Certificates {
		out += fmt.Sprint(c)
	}
	return out
}
