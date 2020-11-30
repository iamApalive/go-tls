package main

import (
	"encoding/binary"
	"fmt"
	. "github.com/viorelyo/tlsExperiment/model"
	"net"
	"os"
)


func connectToServer(srvAddr string) net.TCPConn {
	fmt.Println("Connecting to server:", srvAddr)
	tcpAddr, err := net.ResolveTCPAddr("tcp", srvAddr)
	if err != nil {
		println("ResolveTCPAddr failed")
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("DailTCP failed:", err.Error())
		os.Exit(1)
	}
	return *conn
}

// https://tls.ulfheim.net/
// https://tools.ietf.org/html/rfc5246#section-7.4.1.4

func sendToServer(conn net.TCPConn, payload []byte) {
	fmt.Println("Sending 'Client Hello' to server")

	_, err := conn.Write(payload)
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
}

func readFromServer(conn net.TCPConn) []byte {
	reply := make([]byte, 600)
	_, err := conn.Read(reply)
	if err != nil {
		println("Read from server failed:", err.Error())
		os.Exit(1)
	}
	//println("reply form server=", string(reply))
	fmt.Printf("Message received from server: %x\n", reply)
	return reply
}

//func parseRecordHeader(answer [5]byte) RecordHeader {
func parseRecordHeader(answer []byte) RecordHeader {
	recordHeader := RecordHeader{}
	recordHeader.Type = answer[0]
	copy(recordHeader.ProtocolVersion[:], answer[1:3])
	copy(recordHeader.Length[:], answer[3:5])
	recordHeader.FooterInt = binary.BigEndian.Uint16(answer[3:5])
	return recordHeader
}

func parseHandshakeHeader(answer []byte) HandshakeHeader {
	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = answer[0]
	copy(handshakeHeader.MessageLength[:], answer[1:4])
	handshakeHeader.FooterInt = binary.BigEndian.Uint32(append([]byte{0}, answer[1:4]...))

	return handshakeHeader
}

func parseExtensionRenegotiationInfo(answer []byte) ExtensionRenegotiationInfo {
	extensionRenegotiationInfo := ExtensionRenegotiationInfo{}
	copy(extensionRenegotiationInfo.Info[:], answer[:2])
	copy(extensionRenegotiationInfo.Length[:], answer[2:4])
	copy(extensionRenegotiationInfo.Payload[:], answer[4:5])
	return extensionRenegotiationInfo
}

func parseHelloServer(answer []byte) (ServerHello, []byte) {
	println("Parsing Server Hello")
	offset := 0
	serverHello := ServerHello{}

	serverHello.RecordHeader = parseRecordHeader(answer[0:5])
	offset += 5

	serverHello.HandshakeHeader = parseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	copy(serverHello.ServerVersion[:], answer[offset:offset+2])
	copy(serverHello.ServerRandom[:], answer[offset+2:offset+34])
	copy(serverHello.SessionIDLenght[:], answer[offset+34:offset+35])

	serverHello.SessionIDLenghtInt = int(serverHello.SessionIDLenght[0])
	if serverHello.SessionIDLenghtInt > 0 {
		serverHello.SessionID = answer[offset+35 : offset+serverHello.SessionIDLenghtInt+35]
		offset += serverHello.SessionIDLenghtInt
		println("copy sessionIDLenght copied len:", serverHello.SessionIDLenghtInt)
	}

	copy(serverHello.CipherSuite[:], answer[offset+35:offset+37])
	copy(serverHello.CompressionMethod[:], answer[offset+37:offset+38])
	copy(serverHello.ExtensionLength[:], answer[offset+38:offset+40])
	//recordHeader.footerInt = binary.BigEndian.Uint16(answer[3:5]) // what is this?
	offset += 40

	serverHello.ExtensionRenegotiationInfo = parseExtensionRenegotiationInfo(answer[offset:])
	offset += 5

	return serverHello, answer[offset:]
}

func parseServerCertificate(answer []byte) (ServerCertificate, []byte) {
	var offset uint32
	offset = 0
	serverCertificate := ServerCertificate{}
	serverCertificate.RecordHeader = parseRecordHeader(answer[:5])
	fmt.Println(answer[:5])

	offset += 5
	serverCertificate.HandshakeHeader = parseHandshakeHeader(answer[offset : offset+4])
	offset += 4
	//serverCertificate.certificatLenght = binary.BigEndian.Uint32(append([]byte{0}, answer[5:8]...))
	copy(serverCertificate.CertificateLength[:], answer[offset:offset+3])
	//handshakeHeader.footerInt = binary.BigEndian.Uint32(append([]byte{0}, answer[1:4]...))
	offset += 3
	copy(serverCertificate.CertificateLengthN[:], answer[offset:offset+3])
	serverCertificate.CertificateLengthInt = binary.BigEndian.Uint32(append([]byte{0}, serverCertificate.CertificateLength[0:3]...))
	println(serverCertificate.CertificateLengthInt)
	//copy(serverCertificate.certificate, answer[offset+11:offset+11+serverCertificate.certificatLenghtInt])

	return serverCertificate, answer[offset:]
}



func main() {
	srvAddr := "ubbcluj.ro:443"
	conn := connectToServer(srvAddr)

	//payload_http := "GET / HTTP/1.1\r\nHost: www.heise.de\r\nSome: hedder\r\n\r\n"
	clientHello := MakeClientHello()

	sendToServer(conn, clientHello.GetClientHelloPayload())
	var answer []byte
	answer = readFromServer(conn)

	serverHello, answer := parseHelloServer(answer)
	fmt.Println(serverHello)

	serverCertificate, answer := parseServerCertificate(answer)
	fmt.Println(serverCertificate)

	conn.Close()


	//for _, k := range clientHello.GetClientHelloPayload() {
	//	fmt.Printf("%x ", k)
	//}
}
