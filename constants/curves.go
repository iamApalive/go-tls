package constants

type CurveConverter struct {
	Curves map[string][2]byte
}

func MakeCurveConverter() CurveConverter {
	CurveConverter := CurveConverter{}
	CurveConverter.Curves = map[string][2]byte{
		"SECP256R1": {0x00, 0x17},
		"SECP384R1": {0x00, 0x18},
		"X25519":    {0x00, 0x1d},
	}

	return CurveConverter
}

func (converter CurveConverter) GetByteCodeForCurve(curve string) [2]byte {
	return converter.Curves[curve]
}

func (converter CurveConverter) GetCurveForByteCode(curve [2]byte) string {
	for k, v := range converter.Curves {
		if v == curve {
			return k
		}
	}

	return ""
}

var GCurves = MakeCurveConverter()
