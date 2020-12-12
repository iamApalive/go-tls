package model

import (
	"fmt"
	"github.com/viorelyo/tlsExperiment/helpers"
)

type Certificate struct {
	Length  [3]byte
	Content []byte
}

type ServerCertificate struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	CertificateLength [3]byte
	Certificates      []Certificate
}

func ParseServerCertificate(answer []byte) (ServerCertificate, []byte) {
	var offset uint32
	offset = 0
	serverCertificate := ServerCertificate{}
	serverCertificate.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverCertificate.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	copy(serverCertificate.CertificateLength[:], answer[offset:offset+3])
	totalCertificateLengthInt := helpers.ConvertByteArrayToInt32(append([]byte{0}, serverCertificate.CertificateLength[0:3]...))
	offset += 3

	fmt.Println(totalCertificateLengthInt)

	// Parsing list of certificates
	var readCertificateLength uint32
	readCertificateLength = 0
	for readCertificateLength < totalCertificateLengthInt {
		currentCertificate := Certificate{}
		copy(currentCertificate.Length[:], answer[offset:offset+3])
		offset += 3

		crtCertificateLengthInt := helpers.ConvertByteArrayToInt32(append([]byte{0}, currentCertificate.Length[0:3]...))
		fmt.Println(crtCertificateLengthInt)

		currentCertificate.Content = answer[offset:offset+crtCertificateLengthInt]
		offset += crtCertificateLengthInt

		serverCertificate.Certificates = append(serverCertificate.Certificates, currentCertificate)
		readCertificateLength += crtCertificateLengthInt + 3 // 3 - size of Length
	}

	return serverCertificate, answer[offset:]
}

func (serverCertificate ServerCertificate) String() string {
	out := fmt.Sprintf("Server Certificate\n")
	out += fmt.Sprint(serverCertificate.RecordHeader)
	out += fmt.Sprint(serverCertificate.HandshakeHeader)
	out += fmt.Sprintf("  Certificate Lenght.: %x\n", serverCertificate.CertificateLength)
	// TODO Display list of certificates
	//out += fmt.Sprintf("  Certificate LenghtN: %x\n", serverCertificate.CertificateLengthN)
	//out += fmt.Sprintf("  Certificate........: %6x\n", serverCertificate.Certificate)
	return out
}
