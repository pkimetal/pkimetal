package request

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

type signed struct {
	ToBeSigned         asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

var (
	oidEcdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidEcdsaWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

func dummySign(toBeSigned []byte, signatureAlgorithm pkix.AlgorithmIdentifier) ([]byte, error) {
	// Package the To-Be-Signed object in a syntactically valid Signed object that the linters will parse.
	dummySigned := signed{
		ToBeSigned:         asn1.RawValue{FullBytes: toBeSigned},
		SignatureAlgorithm: signatureAlgorithm,
	}

	// For ECDSA signature algorithms, produce a dummy signature that will satisfy the e_mp_ecdsa_signature_encoding_correct lint
	if signatureAlgorithm.Algorithm.Equal(oidEcdsaWithSHA256) { // ecdsa-with-SHA256
		dummySigned.SignatureValue.Bytes = []byte{
			0x30, 0x46, 0x02, 0x21, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
			0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x02, 0x21, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
			0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
		}
	} else if signatureAlgorithm.Algorithm.Equal(oidEcdsaWithSHA384) { // ecdsa-with-SHA384
		dummySigned.SignatureValue.Bytes = []byte{
			0x30, 0x66, 0x02, 0x31, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
			0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
			0x89, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x31, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
			0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
			0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
		}
	}

	// DER-encode the dummy certificate.
	return asn1.Marshal(dummySigned)
}
