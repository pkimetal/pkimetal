package request

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestGetPOSTEndpoint(t *testing.T) {
	var ri RequestInfo
	if !ri.GetPOSTEndpoint("lintcert") || ri.endpoint != ENDPOINT_LINTCERT {
		t.Errorf("lintcert: got endpoint %d ok=%v", ri.endpoint, ri.endpoint == ENDPOINT_LINTCERT)
	}
	if ri.GetPOSTEndpoint("not-an-endpoint") {
		t.Error("expected false for an unknown endpoint")
	}
}

func TestGetInput_FormURLEncodedCertificate(t *testing.T) {
	der := testcaseDER(t, "tls_ov_certificate.crt")
	form := url.Values{}
	form.Set("b64input", base64.StdEncoding.EncodeToString(der))
	ctx := newPostCtx("application/x-www-form-urlencoded", []byte(form.Encode()))

	ri := RequestInfo{endpoint: ENDPOINT_LINTCERT}
	if err := ri.GetInput(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ri.cert == nil {
		t.Fatal("expected a parsed certificate")
	}
}

func TestGetInput_FormEndpointSpecificKey(t *testing.T) {
	// The endpoint-specific "b64cert" key is accepted for the lintcert endpoint.
	der := testcaseDER(t, "tls_ov_certificate.crt")
	form := url.Values{}
	form.Set(INPUTSTRING_B64CERT, base64.StdEncoding.EncodeToString(der))
	ctx := newPostCtx("application/x-www-form-urlencoded", []byte(form.Encode()))

	ri := RequestInfo{endpoint: ENDPOINT_LINTCERT}
	if err := ri.GetInput(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ri.cert == nil {
		t.Fatal("expected a parsed certificate")
	}
}

func TestGetInput_PkixCertificate(t *testing.T) {
	der := testcaseDER(t, "tls_ov_certificate.crt")
	ctx := newPostCtx("application/pkix-cert", der)

	ri := RequestInfo{endpoint: ENDPOINT_LINTCERT}
	if err := ri.GetInput(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ri.cert == nil {
		t.Fatal("expected a parsed certificate")
	}
}

func TestGetInput_Errors(t *testing.T) {
	der := testcaseDER(t, "tls_ov_certificate.crt")

	cases := []struct {
		name        string
		endpoint    Endpoint
		contentType string
		body        []byte
	}{
		{"unsupported content type", ENDPOINT_LINTCERT, "text/plain", der},
		{"pkix-cert on wrong endpoint", ENDPOINT_LINTCRL, "application/pkix-cert", der},
		{"pkix-crl on wrong endpoint", ENDPOINT_LINTCERT, "application/pkix-crl", der},
		{"octet-stream on non-tbs endpoint", ENDPOINT_LINTCERT, "application/octet-stream", der},
		{"form without recognised input", ENDPOINT_LINTCERT, "application/x-www-form-urlencoded", []byte("foo=bar")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newPostCtx(c.contentType, c.body)
			ri := RequestInfo{endpoint: c.endpoint}
			if err := ri.GetInput(ctx); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}
