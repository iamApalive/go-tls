package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/helpers"
	. "github.com/viorelyo/tlsExperiment/model"
	"io"
	"net"
	"os"
)

func connectToServer(srvAddr string) net.TCPConn {
	log.Info("Connecting to server:", srvAddr)

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

func sendToServer(conn net.TCPConn, payload []byte) {
	log.Info("Sending 'Client Hello' to server")

	_, err := conn.Write(payload)
	if err != nil {
		println("Write to server failed:", err.Error())
		_ = conn.Close()
		os.Exit(1)
	}
}

func readFromServer(conn net.TCPConn) []byte {
	log.Info("Reading response")

	record := make([]byte, 5)
	// using io.ReadFull to block Read until whole data is sent from server (https://stackoverflow.com/questions/26999615/go-tcp-read-is-non-blocking)
	_, err := io.ReadFull(&conn, record)
	if err != nil {
		println("Read from server failed:", err.Error())
		_ = conn.Close()
		os.Exit(1)
	}

	recordHeader := ParseRecordHeader(record)
	recordLen := int(helpers.ConvertByteArrayToUInt16(recordHeader.Length))

	buffer := make([]byte, recordLen)
	_, err = io.ReadFull(&conn, buffer)
	if err != nil {
		println("Read from server failed:", err.Error())
		_ = conn.Close()
		os.Exit(1)
	}

	record = append(record, buffer...)

	log.Debug("Message received from server: %x\n", record)
	return record
}

func initLogger() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
}

// TODO maybe dump each part of handshake to JSON file
func main() {
	initLogger()

	srvAddr := "ubbcluj.ro:443"
	conn := connectToServer(srvAddr)
	defer conn.Close()

	clientHello := MakeClientHello()
	fmt.Println(clientHello)
	//clientHello.SaveJSON()

	sendToServer(conn, clientHello.GetClientHelloPayload())

	var answer []byte

	answer = readFromServer(conn)
	serverHello, _, err := ParseServerHello(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverHello)
	//serverHello.SaveJSON()

	answer = readFromServer(conn)
	serverCertificate, _, err := ParseServerCertificate(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverCertificate)
	//serverCertificate.SaveJSON()

	answer = readFromServer(conn)
	serverKeyExchange, _, err := ParseServerKeyExchange(answer)
	if err != nil {
		log.Warn(err)
	} else {
		fmt.Println(serverKeyExchange)
		//serverKeyExchange.SaveJSON()
		answer = readFromServer(conn)
	}

	serverHelloDone, _, err := ParseServerHelloDone(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverHelloDone)
	//serverHelloDone.SaveJSON()

	// TODO Compute client stuff -> Send To Server
	//sendToServer(conn, clientHello.GetClientHelloPayload())
	//answer = readFromServer(conn)
	//serverHello1, _, err := ParseServerHello(answer)
	//fmt.Println(serverHello1)
}
