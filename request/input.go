package request

import (
	"encoding/base64"
	"fmt"

	"github.com/pkimetal/pkimetal/utils"

	"github.com/valyala/fasthttp"
)

const (
	INPUTSTRING_B64CERT    = "b64cert"
	INPUTSTRING_B64TBSCERT = "b64tbscert"
	INPUTSTRING_B64CRL     = "b64crl"
	INPUTSTRING_B64TBSCRL  = "b64tbscrl"
	INPUTSTRING_B64OCSP    = "b64ocsp"
	INPUTSTRING_B64TBSOCSP = "b64tbsocsp"
)

var input = map[Endpoint]string{
	ENDPOINT_LINTCERT:    INPUTSTRING_B64CERT,
	ENDPOINT_LINTTBSCERT: INPUTSTRING_B64TBSCERT,
	ENDPOINT_LINTCRL:     INPUTSTRING_B64CRL,
	ENDPOINT_LINTTBSCRL:  INPUTSTRING_B64TBSCRL,
	ENDPOINT_LINTOCSP:    INPUTSTRING_B64OCSP,
	ENDPOINT_LINTTBSOCSP: INPUTSTRING_B64TBSOCSP,
}

func (ri *RequestInfo) GetInput(fhctx *fasthttp.RequestCtx) error {
	switch utils.B2S(fhctx.Request.Header.ContentType()) {
	case "application/x-www-form-urlencoded":
		args := fhctx.PostArgs()
		if i, ok := input[ri.endpoint]; ok {
			ri.b64Input = args.Peek(i)
		}

		if len(ri.b64Input) == 0 {
			ri.b64Input = args.Peek("b64input")
		}

		if len(ri.b64Input) == 0 {
			return fmt.Errorf("input not found")
		}

	case "application/pkix-cert":
		if ri.endpoint != ENDPOINT_LINTCERT {
			return fmt.Errorf("invalid endpoint for certificate input")
		}

	case "application/pkix-crl":
		if ri.endpoint != ENDPOINT_LINTCRL {
			return fmt.Errorf("invalid endpoint for CRL input")
		}

	case "application/ocsp-response":
		if ri.endpoint != ENDPOINT_LINTOCSP {
			return fmt.Errorf("invalid endpoint for OCSP response input")
		}

	case "application/octet-stream":
		if ri.endpoint != ENDPOINT_LINTTBSCERT && ri.endpoint != ENDPOINT_LINTTBSCRL && ri.endpoint != ENDPOINT_LINTTBSOCSP {
			return fmt.Errorf("invalid content type for this endpoint")
		}

	default:
		return fmt.Errorf("unsupported content type")
	}

	if ri.b64Input == nil {
		ri.b64Input = make([]byte, base64.StdEncoding.EncodedLen(len(fhctx.PostBody())))
		base64.StdEncoding.Encode(ri.b64Input, fhctx.PostBody())
	}

	var err error
	if (ri.endpoint == ENDPOINT_LINTCERT) || (ri.endpoint == ENDPOINT_LINTTBSCERT) {
		ri.cert, err = ri.parseCertificateInput()
		return err
	} else if (ri.endpoint == ENDPOINT_LINTCRL) || (ri.endpoint == ENDPOINT_LINTTBSCRL) {
		return ri.parseCRLInput()
	} else if (ri.endpoint == ENDPOINT_LINTOCSP) || (ri.endpoint == ENDPOINT_LINTTBSOCSP) {
		return ri.parseOCSPResponseInput()
	} else {
		return nil
	}
}
