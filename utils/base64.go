package utils

import (
	"encoding/base64"
	"encoding/pem"
)

func DecodePEMOrBase64(input []byte, expectedHeader string) ([]byte, error) {
	if block, _ := pem.Decode(input); block != nil && block.Type == expectedHeader {
		return block.Bytes, nil
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	n, err := base64.StdEncoding.Decode(decoded, input)
	if err != nil {
		return nil, err
	} else {
		return decoded[0:n], nil
	}
}
