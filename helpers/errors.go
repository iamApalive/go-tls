package helpers

type ParsingError struct {
	IsServerHelloParsingError       bool
	IsServerKeyExchangeMissingError bool
	IsServerHelloMissingError       bool
	IsServerCertificateMissingError bool
	IsServerHelloDoneMissingError   bool
	IsServerChangeCipherSpecError   bool
	IsServerHandshakeFinishedError  bool
}

func (pe *ParsingError) Error() string {
	if pe.IsServerHelloParsingError {
		return "ServerHello parsing error encountered!"
	}
	if pe.IsServerHelloMissingError {
		return "ServerHello missing!"
	}
	if pe.IsServerCertificateMissingError {
		return "ServerCertificate missing!"
	}
	if pe.IsServerKeyExchangeMissingError {
		return "ServerKeyExchange missing!"
	}
	if pe.IsServerHelloDoneMissingError {
		return "ServerHelloDone missing!"
	}
	if pe.IsServerChangeCipherSpecError {
		return "ServerChangeCipherSpec missing!"
	}
	if pe.IsServerHandshakeFinishedError {
		return "ServerHandshakeFinished missing!"
	}
	return "Undefined error"
}

func ServerHelloParsingError() error {
	return &ParsingError{IsServerHelloParsingError: true}
}

func ServerHelloMissingError() error {
	return &ParsingError{IsServerHelloMissingError: true}
}

func ServerCertificateMissingError() error {
	return &ParsingError{IsServerCertificateMissingError: true}
}

func ServerKeyExchangeMissingError() error {
	return &ParsingError{IsServerKeyExchangeMissingError: true}
}

func ServerHelloDoneMissingError() error {
	return &ParsingError{IsServerHelloDoneMissingError: true}
}

func ServerChangeCipherSpecError() error {
	return &ParsingError{IsServerChangeCipherSpecError: true}
}

func ServerHandshakeFinishedError() error {
	return &ParsingError{IsServerHandshakeFinishedError: true}
}
