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
	// TODO - think about some generalization (maybe struct containing output length)
	hashedOutput := hashFunc.Sum(byteArray)
	return hashedOutput[len(hashedOutput)-sha512.Size384:]
}
