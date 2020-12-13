package main

import (
	"fmt"
	. "github.com/viorelyo/tlsExperiment/model"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
)


func connectToServer(srvAddr string) net.Conn {
	log.Info("Connecting to server:", srvAddr)

	conn, err := net.Dial("tcp", srvAddr)
	if err != nil {
		println("DailTCP failed:", err.Error())
		os.Exit(1)
	}

	return conn
}

func sendToServer(conn net.Conn, payload []byte) {
	log.Info("Sending 'Client Hello' to server")

	_, err := conn.Write(payload)
	if err != nil {
		println("Write to server failed:", err.Error())
		_ = conn.Close()
		os.Exit(1)
	}

	conn.(*net.TCPConn).CloseWrite()
}

func readFromServer(conn net.Conn) []byte {
	log.Info("Reading response")

	var reply []byte
	reply, err := ioutil.ReadAll(conn)
	if err != nil {
		println("Read from server failed:", err.Error())
		conn.Close()
		os.Exit(1)
	}

	fmt.Printf("Message received from server: %x\n", reply)
	return reply
}


func initLogger() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors: true,
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

	sendToServer(conn, clientHello.GetClientHelloPayload())
	var answer []byte
	answer = readFromServer(conn)

	serverHello, answer, err := ParseServerHello(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverHello)

	serverCertificate, answer, err := ParseServerCertificate(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverCertificate)

	serverKeyExchange, answer, err := ParseServerKeyExchange(answer)
	if err != nil {
		log.Warn(err)
	} else {
		fmt.Println(serverKeyExchange)
	}

	serverHelloDone,answer, err := ParseServerHelloDone(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	fmt.Println(serverHelloDone)
}
