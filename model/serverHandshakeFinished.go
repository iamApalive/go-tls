package model

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/coreUtils"
	"github.com/viorelyo/tlsExperiment/cryptoHelpers"
	"github.com/viorelyo/tlsExperiment/helpers"
	"os"
)

type ServerHandshakeFinished struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	VerifyData      []byte
}

func ParseServerHandshakeFinished(serverKey, serverIV, answer []byte, seqNum byte) (ServerHandshakeFinished, []byte, error) {
	var offset uint32
	offset = 0

	serverHandshakeFinished := ServerHandshakeFinished{}
	serverHandshakeFinished.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	if serverHandshakeFinished.RecordHeader.Type != constants.RecordHandshake {
		log.Error("RecordType mismatch")
		return serverHandshakeFinished, answer, helpers.ServerHandshakeFinishedError()
	}

	encryptedContent := answer[offset:]

	additionalData := coreUtils.MakeAdditionalData(seqNum, serverHandshakeFinished.RecordHeader.Type, serverHandshakeFinished.RecordHeader.ProtocolVersion)
	plaintext := cryptoHelpers.Decrypt(serverKey, serverIV, encryptedContent, additionalData)

	offset = 0
	serverHandshakeFinished.HandshakeHeader = ParseHandshakeHeader(plaintext[offset : offset+4])
	offset += 4

	if serverHandshakeFinished.HandshakeHeader.MessageType != constants.HandshakeServerFinished {
		log.Error("HandshakeType mismatch")
		return serverHandshakeFinished, answer, helpers.ServerHandshakeFinishedError()
	}

	serverHandshakeFinished.VerifyData = plaintext[offset:]

	return serverHandshakeFinished, answer, nil
}

func (serverHandshakeFinished ServerHandshakeFinished) SaveJSON() {
	file, _ := os.OpenFile("ServerHandshakeFinished.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverHandshakeFinished)
}

func (serverHandshakeFinished ServerHandshakeFinished) String() string {
	out := fmt.Sprintf("Server Handshake Finished\n")
	out += fmt.Sprint(serverHandshakeFinished.RecordHeader)
	out += fmt.Sprint(serverHandshakeFinished.HandshakeHeader)
	out += fmt.Sprintf("  VerifyData.........: %6x\n", serverHandshakeFinished.VerifyData)
	return out
}

func (serverHandshakeFinished *ServerHandshakeFinished) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
		VerifyData      []byte          `json:"VerifyData"`
	}{
		RecordHeader:    serverHandshakeFinished.RecordHeader,
		HandshakeHeader: serverHandshakeFinished.HandshakeHeader,
		VerifyData:      serverHandshakeFinished.VerifyData,
	})
}
