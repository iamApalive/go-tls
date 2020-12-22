package cryptoHelpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/viorelyo/tlsExperiment/constants"
	"github.com/viorelyo/tlsExperiment/helpers"
	"io"
)

func Encrypt(key []byte, iv []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	// TODO - 8 define as AESGCM.nonce_size
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	nonceIV := append(iv, nonce...)

	version := constants.GTlsVersions.GetByteCodeForVersion("TLS 1.2")
	additionalData := make([]byte, 8)
	additionalData = append(additionalData, 0x16)
	additionalData = append(additionalData, version[:]...)

	contentBytesLength := helpers.ConvertIntToByteArray(uint16(len(plaintext)))
	additionalData = append(additionalData, contentBytesLength[:]...)

	aesgcm, err := cipher.NewGCM(block)
	//if err != nil {
	//	panic(err.Error())
	//}

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data (aad) and returns ciphertext together with authentication tag.
	ciphertext := aesgcm.Seal(nil, nonceIV, plaintext, additionalData)
	// TODO check if nil

	return append(nonce, ciphertext...)
}
