package request

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/pkimetal/pkimetal/utils"
)

type BasicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type ResponseASN1 struct {
	Status   asn1.Enumerated
	Response ResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ResponseStatus int

const Success ResponseStatus = 0

var sha256WithRSAEncryption = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue}

func (ri *RequestInfo) parseOCSPResponseInput() error {
	// Decode the PEM or Base64 OCSP response input.
	var err error
	if ri.b64Input == nil {
		return fmt.Errorf("no OCSP response provided")
	} else if ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "OCSP RESPONSE"); err != nil {
		return err
	}

	// Process the input based on the endpoint.
	switch ri.endpoint {
	case ENDPOINT_LINTTBSOCSP:
		if err = ri.makeDummyOCSPResponse(); err != nil {
			return err
		}
	case ENDPOINT_LINTOCSP:
	default:
		return fmt.Errorf("invalid endpoint for OCSP response input")
	}

	// Update the Base64 input field from the processed input, which will ensure that PEM encapsulation boundaries are present.
	ri.b64Input = pem.EncodeToMemory(&pem.Block{
		Type:  "OCSP RESPONSE",
		Bytes: ri.decodedInput,
	})

	return nil
}

func (ri *RequestInfo) makeDummyOCSPResponse() error {
	// Construct and encode the BasicResponse, using a dummy empty signature.
	basicRespDER, err := asn1.Marshal(BasicResponse{
		TBSResponseData:    asn1.RawValue{FullBytes: ri.decodedInput},
		SignatureAlgorithm: sha256WithRSAEncryption,
		Signature:          asn1.BitString{},
	})
	if err != nil {
		return err
	}

	ri.decodedInput, err = asn1.Marshal(ResponseASN1{
		Status: asn1.Enumerated(Success),
		Response: ResponseBytes{
			ResponseType: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}), // id-pkix-ocsp-basic
			Response:     basicRespDER,
		},
	})
	return err
}
