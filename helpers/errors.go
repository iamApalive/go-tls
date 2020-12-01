package helpers

type ParsingError struct {
	IsServerHelloParsingError bool
}

func (pe *ParsingError) Error() string {
	if pe.IsServerHelloParsingError {
		return "ServerHello parsing error encountered!"
	}
	return "Undefined error"
}

func ServerHelloParsingError() error {
	return &ParsingError{IsServerHelloParsingError: true}
}
