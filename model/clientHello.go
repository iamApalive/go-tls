package model


type ClientHello struct {
	recordHeader 			   RecordHeader
	handshakeHeader            HandshakeHeader
	clientVersion              [2]byte
	clientRandom               [32]byte
	sessionIDLength            [1]byte
	sessionIDLenghtInt         int
	sessionID                  []byte
	cipherSuitesLength		   [2]byte
	cipherSuites               []byte
	compressionMethodsLength   [1]byte
	compressionMethods         []byte
	// extensionLength            [2]byte
}
