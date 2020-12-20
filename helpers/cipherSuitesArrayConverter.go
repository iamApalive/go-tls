package helpers

import (
	"github.com/viorelyo/tlsExperiment/constants"
)

func ConvertByteArrayToCipherSuites(byteArray []byte) []string {
	var cipherSuites []string
	for i := 0; i < len(byteArray); i += 2 {
		suiteArray := [2]byte{byteArray[i], byteArray[i+1]}
		cipherSuites = append(cipherSuites, constants.GCipherSuites.GetSuiteForByteCode(suiteArray))
	}
	return cipherSuites
}
