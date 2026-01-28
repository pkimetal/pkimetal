package request

import (
	"encoding/pem"
	"fmt"

	"github.com/pkimetal/pkimetal/utils"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509/pkix"
)

type tbsCertListPartial struct {
	Version            int `asn1:"optional"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
}

func (ri *RequestInfo) parseCRLInput() error {
	// Decode the PEM or Base64 CRL input.
	var err error
	if ri.b64Input == nil {
		return fmt.Errorf("no CRL provided")
	} else if ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "X509 CRL"); err != nil {
		return err
	}

	// Process the input based on the endpoint.
	switch ri.endpoint {
	case ENDPOINT_LINTTBSCRL:
		if err = ri.makeDummyCRL(); err != nil {
			return err
		}
	case ENDPOINT_LINTCRL:
	default:
		return fmt.Errorf("invalid endpoint for CRL input")
	}

	// Update the Base64 input field from the processed input, which will ensure that PEM encapsulation boundaries are present.
	ri.b64Input = pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: ri.decodedInput,
	})

	return nil
}

func (ri *RequestInfo) makeDummyCRL() error {
	// Decode enough of the TBSCertList to discover the signature algorithm.
	var tbs tbsCertListPartial
	var err error
	if _, err = asn1.Unmarshal(ri.decodedInput, &tbs); err != nil {
		return err
	}

	// Wrap the TBSCertList in a dummy signature.
	ri.decodedInput, err = dummySign(ri.decodedInput, tbs.SignatureAlgorithm)
	return err
}
