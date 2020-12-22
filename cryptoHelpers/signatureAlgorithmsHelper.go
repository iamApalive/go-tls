package cryptoHelpers

import (
	"crypto/sha512"
	"hash"
)

// Apply hashing function based on given name to hash message
func HashByteArray(algorithmName string, byteArray []byte) []byte {
	var hashFactory = map[string]func() hash.Hash{
		"SHA384": sha512.New384,
	}

	hashFunc := hashFactory[algorithmName]()
	return hashFunc.Sum(byteArray)
}
