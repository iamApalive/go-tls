package cryptoHelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
	"io"
)

const (
	AESGCM_NonceSize = 8
)

// TODO extract seqNumber & record type from parameters
func Encrypt(key, iv, plaintext []byte, seqNumber byte, recordType byte) []byte {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(aes)
	//if err != nil {
	//	panic(err.Error())
	//}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, AESGCM_NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	nonceIV := append(iv, nonce...)

	version := constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	additionalData := make([]byte, 7)
	additionalData = append(additionalData, seqNumber)
	additionalData = append(additionalData, recordType)
	additionalData = append(additionalData, version[:]...)

	contentBytesLength := helpers.ConvertIntToByteArray(uint16(len(plaintext)))
	additionalData = append(additionalData, contentBytesLength[:]...)

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data (aad) and returns ciphertext together with authentication tag.
	ciphertext := aesgcm.Seal(nil, nonceIV, plaintext, additionalData)
	// TODO check if nil

	return append(nonce, ciphertext...)
}

func Decrypt(serverKey, serverIV, ciphertext []byte, seqNumber byte, recordType byte) []byte {
	aes, err := aes.NewCipher(serverKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(aes)
	//if err != nil {
	//	panic(err.Error())
	//}

	nonce, rest := ciphertext[:AESGCM_NonceSize], ciphertext[AESGCM_NonceSize:]
	nonceIV := append(serverIV, nonce...)

	version := constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	additionalData := make([]byte, 7)
	additionalData = append(additionalData, seqNumber)
	additionalData = append(additionalData, recordType)
	additionalData = append(additionalData, version[:]...)

	contentBytesLength := helpers.ConvertIntToByteArray(uint16(len(rest) - 16))
	additionalData = append(additionalData, contentBytesLength[:]...)

	plaintext, err := aesgcm.Open(nil, nonceIV, rest, additionalData)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}
