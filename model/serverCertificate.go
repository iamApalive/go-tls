package model

import "fmt"

type ServerCertificate struct {
	RecordHeader         RecordHeader
	HandshakeHeader      HandshakeHeader
	CertificateLength    [3]byte
	CertificateLengthInt uint32  /// apparently there can be more than one cert, this must be accounted for..
	CertificateLengthN   [3]byte // this must be a array of arrays?
	certificate          []byte  // certificateN [][]byte
}

func (serverCertificate ServerCertificate) String() string {
	out := fmt.Sprintf("Server Certificate\n")
	out += fmt.Sprint(serverCertificate.RecordHeader)
	out += fmt.Sprint(serverCertificate.HandshakeHeader)
	out += fmt.Sprintf("  Certificate Lenght.: %x\n", serverCertificate.CertificateLength)
	out += fmt.Sprintf("  Certificate LenghtN: %x\n", serverCertificate.CertificateLengthN)
	out += fmt.Sprintf("  Certificate........: %x\n", serverCertificate.certificate)
	return out
}
