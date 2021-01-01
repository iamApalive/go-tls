package core

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/coreUtils"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
	"github.com/viorelyo/tlsExperiment/model"
	"io"
	"net"
	"os"
)

type TLSClient struct {
	jsonVerbose     bool
	host            string
	conn            net.TCPConn
	messages        []byte
	clientSeqNumber uint8
	serverSeqNumber uint8
	cipherSuite     constants.CipherSuiteInfo
	securityParams  coreUtils.SecurityParams
}

func MakeTLSClient(host string, jsonVerbose bool) *TLSClient {
	tlsClient := TLSClient{
		jsonVerbose:     jsonVerbose,
		host:            host,
		conn:            connectToServer(host + ":443"),
		clientSeqNumber: 0,
		serverSeqNumber: 0,
	}

	return &tlsClient
}

func connectToServer(srvAddr string) net.TCPConn {
	log.Info("Connecting to server:", srvAddr)

	tcpAddr, err := net.ResolveTCPAddr("tcp", srvAddr)
	if err != nil {
		log.Error("ResolveTCPAddr failed")
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Error("DailTCP failed:", err.Error())
		os.Exit(1)
	}

	return *conn
}

func (client *TLSClient) Terminate() {
	err := client.conn.Close()
	if err != nil {
		log.Error(err)
	}
}

func (client *TLSClient) Execute() {
	client.sendClientHello()
	client.readServerResponse()
	client.performClientHandshake()
	client.readServerHandshakeFinished()
	client.sendApplicationData()
	client.receiveApplicationData()
}

func (client *TLSClient) sendToServer(payload []byte) {
	log.Info("Sending to server")

	_, err := client.conn.Write(payload)
	if err != nil {
		log.Error("Write to server failed:", err.Error())
		client.Terminate()
		os.Exit(1)
	}
}

func (client *TLSClient) readFromServer() []byte {
	log.Info("Reading response")

	record := make([]byte, 5)
	// using io.ReadFull to block Read until whole data is sent from server (https://stackoverflow.com/questions/26999615/go-tcp-read-is-non-blocking)
	_, err := io.ReadFull(&client.conn, record)
	if err != nil {
		log.Error("Read from server failed:", err.Error())
		client.Terminate()
		os.Exit(1)
	}

	recordHeader := model.ParseRecordHeader(record)
	recordLen := int(helpers.ConvertByteArrayToUInt16(recordHeader.Length))

	buffer := make([]byte, recordLen)
	_, err = io.ReadFull(&client.conn, buffer)
	if err != nil {
		log.Error("Read from server failed:", err.Error())
		client.Terminate()
		os.Exit(1)
	}

	record = append(record, buffer...)

	log.Debug("Message received from server: %x\n", record)
	return record
}

func (client *TLSClient) sendClientHello() {
	clientHello := model.MakeClientHello()
	client.securityParams.ClientRandom = clientHello.ClientRandom
	clientHelloPayload := clientHello.GetClientHelloPayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientHelloPayload)...)
	if client.jsonVerbose {
		clientHello.SaveJSON()
	} else {
		fmt.Println(clientHello)
	}

	client.sendToServer(clientHelloPayload)
}

func (client *TLSClient) readServerResponse() {
	var answer []byte

	answer = client.readFromServer()
	serverHello, _, err := model.ParseServerHello(answer)
	if err != nil {
		log.Warn(err)
		client.Terminate()
		os.Exit(1)
	}
	client.cipherSuite = *constants.GCipherSuites.GetSuiteInfoForByteCode(serverHello.CipherSuite)
	client.securityParams.ServerRandom = serverHello.ServerRandom
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
	if client.jsonVerbose {
		serverHello.SaveJSON()
	} else {
		fmt.Println(serverHello)
	}

	answer = client.readFromServer()
	serverCertificate, _, err := model.ParseServerCertificate(answer)
	if err != nil {
		log.Warn(err)
		client.Terminate()
		os.Exit(1)
	}
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
	if client.jsonVerbose {
		serverCertificate.SaveJSON()
	} else {
		fmt.Println(serverCertificate)
	}

	answer = client.readFromServer()
	serverKeyExchange, _, err := model.ParseServerKeyExchange(answer)
	if err != nil {
		log.Warn(err)
	} else {
		client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
		if client.jsonVerbose {
			serverKeyExchange.SaveJSON()
		} else {
			fmt.Println(serverKeyExchange)
		}
		answer = client.readFromServer()
	}
	client.securityParams.ServerKeyExchangePublicKey = serverKeyExchange.PublicKey
	client.securityParams.Curve = constants.GCurves.GetCurveInfoForByteCode(serverKeyExchange.CurveID).Curve
	// TODO verify signature: the computed signature for SHA256(client_hello_random + server_hello_random + curve_info + public_key)

	serverHelloDone, _, err := model.ParseServerHelloDone(answer)
	if err != nil {
		log.Warn(err)
		client.Terminate()
		os.Exit(1)
	}
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
	if client.jsonVerbose {
		serverHelloDone.SaveJSON()
	} else {
		fmt.Println(serverHelloDone)
	}
}

func (client *TLSClient) performClientHandshake() {
	clientKeyExchange := model.MakeClientKeyExchange()
	client.securityParams.ClientKeyExchangePrivateKey = clientKeyExchange.PrivateKey
	clientKeyExchangePayload := clientKeyExchange.GetClientKeyExchangePayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientKeyExchangePayload)...)
	if client.jsonVerbose {
		// TODO - implement
		//clientKeyExchange.SaveJSON()
	} else {
		fmt.Println(clientKeyExchange)
	}

	clientChangeCipherSpec := model.MakeClientChangeCipherSpec()
	//clientChangeCipherSpec is not a handshake message, so it is not included in the hash input

	data := cryptoHelpers.HashByteArray(client.cipherSuite.HashingAlgorithm, client.messages)
	verifyData := cryptoHelpers.MakeVerifyData(&client.securityParams, data)
	if verifyData == nil {
		client.Terminate()
		os.Exit(1)
	}

	// TODO Compute client stuff -> Send To Server
	clientHandshakeFinished := model.MakeClientHandshakeFinished(client.securityParams.ClientIV, verifyData)
	if client.jsonVerbose {
		// TODO - implement
		//clientHandshakeFinished.SaveJSON()
	} else {
		// TODO - implement
		//fmt.Println(clientHandshakeFinished)
	}

	// TODO extract sequence number as global parameter somehow + record type
	encryptedContent := cryptoHelpers.Encrypt(client.securityParams.ClientKey, client.securityParams.ClientIV, clientHandshakeFinished.GetClientHandshakeFinishedPlaintextPayload(), client.clientSeqNumber, 0x16)
	client.clientSeqNumber += 1

	// Send ClientKeyExchange, ClientChangeCipherSpec, ClientHandshakeFinished on the same tcp connection
	finalPayload := append(clientKeyExchangePayload, clientChangeCipherSpec.GetClientChangeCipherSpecPayload()...)
	finalPayload = append(finalPayload, clientHandshakeFinished.GetClientHandshakeFinishedPayload(encryptedContent)...)

	client.sendToServer(finalPayload)
}

func (client *TLSClient) readServerHandshakeFinished() {
	// TODO - Parse responses
	answer := client.readFromServer()
	if client.jsonVerbose {
		// TODO - implement
	} else {
		// TODO - implement
	}
	log.Debug(answer)

	answer = client.readFromServer()
	if client.jsonVerbose {
		// TODO - implement
	} else {
		// TODO - implement
	}
	log.Debug(answer)
	client.serverSeqNumber += 1
}

func (client *TLSClient) sendApplicationData() {
	// TODO - Parameterize request data
	requestData := "GET / HTTP/1.1\r\nHost: " + client.host + "\r\n\r\n"

	clientApplicationData := model.MakeApplicationData(client.securityParams.ClientKey, client.securityParams.ClientIV, []byte(requestData))
	client.sendToServer(clientApplicationData.GetPayload())
}

func (client *TLSClient) receiveApplicationData() {
	answer := client.readFromServer()
	log.Debug(answer)

	serverApplicationData := model.ParseApplicationData(client.securityParams.ServerKey, client.securityParams.ServerIV, answer, client.serverSeqNumber)
	client.serverSeqNumber += 1
	log.Info("Plaintext: ", string(serverApplicationData.Data))

	answer = client.readFromServer()
	log.Debug(answer)

	serverApplicationData = model.ParseApplicationData(client.securityParams.ServerKey, client.securityParams.ServerIV, answer, client.serverSeqNumber)
	client.serverSeqNumber += 1
	log.Info("Plaintext: ", string(serverApplicationData.Data))
}
