package main

import (
	"crypto/elliptic"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
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
	
	var messages []byte

	clientHello := MakeClientHello()
	clientHelloPayload := clientHello.GetClientHelloPayload()
	messages = append(messages, helpers.IgnoreRecordHeader(clientHelloPayload)...)
	fmt.Println(clientHello)
	//clientHello.SaveJSON()

	sendToServer(conn, clientHelloPayload)

	var answer []byte

	answer = readFromServer(conn)
	serverHello, _, err := ParseServerHello(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	messages = append(messages, helpers.IgnoreRecordHeader(answer)...)
	fmt.Println(serverHello)
	//serverHello.SaveJSON()

	answer = readFromServer(conn)
	serverCertificate, _, err := ParseServerCertificate(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	messages = append(messages, helpers.IgnoreRecordHeader(answer)...)
	fmt.Println(serverCertificate)
	//serverCertificate.SaveJSON()

	answer = readFromServer(conn)
	serverKeyExchange, _, err := ParseServerKeyExchange(answer)
	if err != nil {
		log.Warn(err)
	} else {
		messages = append(messages, helpers.IgnoreRecordHeader(answer)...)
		fmt.Println(serverKeyExchange)
		//serverKeyExchange.SaveJSON()
		answer = readFromServer(conn)
	}
	// TODO verify signature: the computed signature for SHA256(client_hello_random + server_hello_random + curve_info + public_key)

	serverHelloDone, _, err := ParseServerHelloDone(answer)
	if err != nil {
		log.Warn(err)
		os.Exit(1)
	}
	messages = append(messages, helpers.IgnoreRecordHeader(answer)...)
	fmt.Println(serverHelloDone)
	//serverHelloDone.SaveJSON()

	clientKeyExchange := MakeClientKeyExchange()
	clientKeyExchangePayload := clientKeyExchange.GetClientKeyExchangePayload()
	sendToServer(conn, clientKeyExchangePayload)

	clientChangeCipherSpec := MakeClientChangeCipherSpec()
	//clientChangeCipherSpec is not a handshake message, so it is not included in the hash input
	sendToServer(conn, clientChangeCipherSpec.GetClientChangeCipherSpecPayload())

	curve := elliptic.P256()
	publicKeyX, publicKeyY := elliptic.Unmarshal(curve, serverKeyExchange.PublicKey)
	if publicKeyX == nil {
		return
	}
	xShared, _ := curve.ScalarMult(publicKeyX, publicKeyY, clientKeyExchange.PrivateKey)
	//TODO why this length?
	sharedKey := make([]byte, (curve.Params().BitSize+7)/8)
	preMasterSecret := xShared.FillBytes(sharedKey)

	log.Info("len is: ", len(preMasterSecret))

	masterSecret := cryptoHelpers.MasterFromPreMasterSecret(preMasterSecret, clientHello.ClientRandom[:], serverHello.ServerRandom[:])
	//clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV := cryptoHelpers.KeysFromMasterSecret(masterSecret, clientHello.ClientRandom[:], serverHello.ServerRandom[:], 0, 384, 4)
	_, _, _, _, clientIV, _ := cryptoHelpers.KeysFromMasterSecret(masterSecret, clientHello.ClientRandom[:], serverHello.ServerRandom[:], 0, 384, 4)

	data := cryptoHelpers.VerifyData("SHA384", messages)
	verifyData := cryptoHelpers.MakeVerifyData(masterSecret, data)

	fmt.Println("master secret: ", masterSecret)
	fmt.Println("verifyData: ", verifyData)

	clientHandshakeFinished := MakeClientHandshakeFinished(clientIV, verifyData)
	sendToServer(conn, clientHandshakeFinished.GetClientHandshakeFinishedPayload())
	answer = readFromServer(conn)
	log.Warn(answer)

	// TODO Compute client stuff -> Send To Server
	//clientHandshakeFinished := MakeClientHandshakeFinished(messages)

	//serverHello1, _, err := ParseServerHello(answer)
	//fmt.Println(serverHello1)
}
