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
	tlsVersion      [2]byte
	jsonVerbose     bool
	host            string
	conn            net.TCPConn
	messages        []byte
	clientSeqNumber uint8
	serverSeqNumber uint8
	cipherSuite     constants.CipherSuiteInfo
	securityParams  coreUtils.SecurityParams
}

func MakeTLSClient(host string, tlsVersion string, jsonVerbose bool) *TLSClient {
	tlsClient := TLSClient{
		tlsVersion:      constants.GTlsVersions.GetByteCodeForVersion(tlsVersion),
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
	clientHello := model.MakeClientHello(client.tlsVersion)
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
	clientKeyExchange, err := model.MakeClientKeyExchange(client.tlsVersion, client.securityParams.Curve)
	if err != nil {
		log.Error(err)
		client.Terminate()
		os.Exit(1)
	}
	client.securityParams.ClientKeyExchangePrivateKey = clientKeyExchange.PrivateKey
	clientKeyExchangePayload := clientKeyExchange.GetClientKeyExchangePayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientKeyExchangePayload)...)
	if client.jsonVerbose {
		clientKeyExchange.SaveJSON()
	} else {
		fmt.Println(clientKeyExchange)
	}

	clientChangeCipherSpec := model.MakeClientChangeCipherSpec(client.tlsVersion)
	//clientChangeCipherSpec is not a handshake message, so it is not included in the hash input

	// TODO maybe move this to MakeClientHandshakeFinished
	data := cryptoHelpers.HashByteArray(client.cipherSuite.HashingAlgorithm, client.messages)
	verifyData := cryptoHelpers.MakeVerifyData(&client.securityParams, data)
	if verifyData == nil {
		log.Error("Could not create VerifyData")
		client.Terminate()
		os.Exit(1)
	}

	clientHandshakeFinished, err := model.MakeClientHandshakeFinished(client.securityParams.ClientKey, client.securityParams.ClientIV, verifyData, client.tlsVersion, client.clientSeqNumber)
	if err != nil {
		log.Error(err)
		client.Terminate()
		os.Exit(1)
	}
	client.clientSeqNumber += 1

	if client.jsonVerbose {
		clientHandshakeFinished.SaveJSON()
	} else {
		fmt.Println(clientHandshakeFinished)
	}

	// Send ClientKeyExchange, ClientChangeCipherSpec, ClientHandshakeFinished on the same tcp connection
	finalPayload := append(clientKeyExchangePayload, clientChangeCipherSpec.GetClientChangeCipherSpecPayload()...)
	finalPayload = append(finalPayload, clientHandshakeFinished.GetClientHandshakeFinishedPayload()...)

	client.sendToServer(finalPayload)
}

func (client *TLSClient) readServerHandshakeFinished() {
	answer := client.readFromServer()
	serverChangeCipherSpec, _, err := model.ParseServerChangeCipherSpec(answer)
	if err != nil {
		log.Warn(err)
		client.Terminate()
		os.Exit(1)
	}

	if client.jsonVerbose {
		serverChangeCipherSpec.SaveJSON()
	} else {
		fmt.Println(serverChangeCipherSpec)
	}

	answer = client.readFromServer()
	serverHandshakeFinished, _, err := model.ParseServerHandshakeFinished(client.securityParams.ServerKey, client.securityParams.ServerIV, answer, 0)
	if err != nil {
		log.Warn(err)
		client.Terminate()
		os.Exit(1)
	}
	client.serverSeqNumber += 1

	if client.jsonVerbose {
		serverHandshakeFinished.SaveJSON()
	} else {
		fmt.Println(serverHandshakeFinished)
	}
}

func (client *TLSClient) sendApplicationData() {
	// TODO - Parameterize request data
	requestData := "GET /ro/ HTTP/1.1\r\nHost: www." + client.host + "\r\n\r\n"

	clientApplicationData, err := model.MakeApplicationData(client.securityParams.ClientKey, client.securityParams.ClientIV, []byte(requestData), client.tlsVersion, client.clientSeqNumber)
	if err != nil {
		log.Error(err)
		client.Terminate()
		os.Exit(1)
	}
	client.sendToServer(clientApplicationData.GetPayload())
}

func (client *TLSClient) receiveApplicationData() {
	var result []byte

	for {
		answer := client.readFromServer()

		serverApplicationData, err := model.ParseApplicationData(client.securityParams.ServerKey, client.securityParams.ServerIV, answer, client.serverSeqNumber)
		if err != nil && serverApplicationData.RecordHeader.Type == constants.RecordEncryptedAlert {
			break
		} else if err != nil {
			log.Error("TLS Error occurred. RecordType found: ", serverApplicationData.RecordHeader.Type)
			break
		}

		result = append(result, serverApplicationData.Data...)
		if string(result[len(result)-5:]) == "\r\n\r\n" {
			break
		}

		client.serverSeqNumber += 1
	}

	fmt.Println("Plaintext: ", string(result))
}
