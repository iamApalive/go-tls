package coreUtils

type AdditionalData struct {
	SeqNumber  byte
	RecordType byte
	TlsVersion [2]byte
}

func MakeAdditionalData(seqNumber byte, recordType byte, tlsVersion [2]byte) *AdditionalData {
	additionalData := AdditionalData{
		SeqNumber:  seqNumber,
		RecordType: recordType,
		TlsVersion: tlsVersion,
	}

	return &additionalData
}
