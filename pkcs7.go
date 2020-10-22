package pkcs7

import "errors"

func Pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	padded := make([]byte, bufLen+padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded, nil
}

func Unpad(padded []byte, size int) ([]byte, error) {
	paddedLen := len(padded)

	if paddedLen%size != 0 {
		return nil, errors.New("pkcs7: Padded value wasn't in correct size.")
	}

	lastPad := padded[paddedLen-1]
	padLen := int(lastPad)
	for i := paddedLen - padLen; i < paddedLen; i++ {
		if padded[i] != lastPad {
			return nil, errors.New("pkcs7: Padded value wasn't in correct format.")
		}
	}

	bufLen := paddedLen - padLen
	buf := make([]byte, bufLen)
	copy(buf, padded[:bufLen])
	return buf, nil
}
