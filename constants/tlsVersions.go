package constants

type TlsVersionConverter struct {
	TlsVersions map[string][2]byte
}

func MakeTlsVersionConverter() TlsVersionConverter {
	tlsVersionConverter := TlsVersionConverter{}
	tlsVersionConverter.TlsVersions = map[string][2]byte {
		"TLS 1.0": [2]byte {3, 1},
		"TLS 1.1": [2]byte {3, 2},
		"TLS 1.2": [2]byte {3, 3},
		"TLS 1.3": [2]byte {3, 4},
	}

	return tlsVersionConverter
}

func (tlsVersionConverter TlsVersionConverter)GetByteCodeForVersion(version string) [2]byte {
	return tlsVersionConverter.TlsVersions[version]
}

func (tlsVersionConverter TlsVersionConverter)GetVersionForByteCode(version [2]byte) string {
	for k, v := range tlsVersionConverter.TlsVersions {
		if v == version {
			return k
		}
	}

	return ""
}


var GTlsVersions = MakeTlsVersionConverter()
