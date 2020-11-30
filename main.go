package main

import (
	"encoding/binary"
	"encoding/hex"
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

func sendToServer(conn net.TCPConn, msgHex string) {

	//var msg []byte
	fmt.Println("Sending 'Client Hello' to server:", msgHex)
	payload, err := hex.DecodeString(msgHex)
	if err != nil {
		println("DecodeString failed:", err.Error())
		os.Exit(1)
	}

	_, err = conn.Write([]byte(payload))
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
	//println("write to server = ", msg)
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
	recordHeader.Ttype = answer[0]
	copy(recordHeader.Protocol_version[:], answer[1:3])
	copy(recordHeader.Footer[:], answer[3:5])
	recordHeader.FooterInt = binary.BigEndian.Uint16(answer[3:5])
	return recordHeader
}

func parseHandshakeHeader(answer []byte) HandshakeHeader {
	handshakeHeader := HandshakeHeader{}
	handshakeHeader.Message_type = answer[0]
	copy(handshakeHeader.Footer[:], answer[1:4])
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

//func initClientHello() []byte {
//	//clientHello := ClientHello{}
//	//
//	//recordHeader := RecordHeader{}
//	//recordHeader.Ttype = 16
//	//recordHeader.Protocol_version =
//
//	//clientHello.RecordHeader = recordHeader
//
//
//	// return
//}

func main() {
	srvAddr := "ubbcluj.ro:443"
	conn := connectToServer(srvAddr)

	//payload_http := "GET / HTTP/1.1\r\nHost: www.heise.de\r\nSome: hedder\r\n\r\n"
	clientHelloPayloadHex := "16030100a5010000a10303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000020cca8cca9c02fc030c02bc02cc013c009c014c00a009c009d002f0035c012000a010000580000001800160000136578616d706c652e756c666865696d2e6e6574000500050100000000000a000a0008001d001700180019000b00020100000d0012001004010403050105030601060302010203ff0100010000120000"
	sendToServer(conn, clientHelloPayloadHex)
	var answer []byte
	answer = readFromServer(conn)

	serverHello, answer := parseHelloServer(answer)
	fmt.Println(serverHello)

	serverCertificate, answer := parseServerCertificate(answer)
	fmt.Println(serverCertificate)

	conn.Close()
}
