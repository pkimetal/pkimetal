package request

import (
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/pkimetal/pkimetal/utils"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

type tbsCertificatePartial struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
}

func (ri *RequestInfo) parseCertificateInput() (*x509.Certificate, error) {
	// Decode the PEM or Base64 certificate input.
	var err error
	if ri.b64Input == nil {
		return nil, fmt.Errorf("no certificate provided")
	} else if ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "CERTIFICATE"); err != nil {
		return nil, err
	}

	// Process the input based on the endpoint.
	switch ri.endpoint {
	case ENDPOINT_LINTTBSCERT:
		if err = ri.makeDummyCertificate(); err != nil {
			return nil, err
		}
	case ENDPOINT_LINTCERT:
	default:
		return nil, fmt.Errorf("invalid endpoint for certificate input")
	}

	// Update the Base64 input field from the processed input, which will ensure that PEM encapsulation boundaries are present.
	ri.b64Input = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ri.decodedInput,
	})

	return x509.ParseCertificate(ri.decodedInput)
}

func (ri *RequestInfo) makeDummyCertificate() error {
	// Decode enough of the TBSCertificate to discover the signature algorithm.
	var tbs tbsCertificatePartial
	var err error
	if _, err = asn1.Unmarshal(ri.decodedInput, &tbs); err != nil {
		return err
	}

	// Wrap the TBSCertificate in a dummy signature.
	ri.decodedInput, err = dummySign(ri.decodedInput, tbs.SignatureAlgorithm)
	return err
}
