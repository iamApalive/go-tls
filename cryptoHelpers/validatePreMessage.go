package cryptoHelpers

func VerifyData(algorithmName string, preMessage []byte) []byte {
	return HashByteArray(algorithmName, preMessage)
}
