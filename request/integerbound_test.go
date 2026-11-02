package request

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"

	"github.com/valyala/fasthttp"
)

// bigIntWithBits returns an odd integer whose bit length is exactly n.
func bigIntWithBits(n int) *big.Int {
	v := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	return v.SetBit(v, 0, 1)
}

// rsaSPKI returns a DER-encoded SubjectPublicKeyInfo for an RSA key with the given modulus.
func rsaSPKI(t *testing.T, modulus *big.Int) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return spki
}

// certWithPublicKey returns a DER-encoded certificate containing pub, signed by a throwaway ECDSA key.
func certWithPublicKey(t *testing.T, pub any) []byte {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestFindOversizedInteger_Fixtures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "testcases"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".crt") && !strings.HasSuffix(e.Name(), ".cer") {
			continue
		}
		der, err := os.ReadFile(filepath.Join("..", "testcases", e.Name()))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if block, _ := pem.Decode(der); block != nil {
			der = block.Bytes
		}
		if n := findOversizedInteger(der, 16384); n != 0 {
			t.Errorf("%s: unexpected oversized %d-bit INTEGER", e.Name(), n)
		}
	}
}

func TestFindOversizedInteger_RSAModulus(t *testing.T) {
	for _, tc := range []struct {
		bits int
		want int
	}{
		{4096, 0},
		{16384, 0},
		{16385, 16385},
		{65536, 65536},
	} {
		cert := certWithPublicKey(t, &rsa.PublicKey{N: bigIntWithBits(tc.bits), E: 65537})
		if got := findOversizedInteger(cert, 16384); got != tc.want {
			t.Errorf("%d-bit modulus: got %d, want %d", tc.bits, got, tc.want)
		}
	}
}

func TestFindOversizedInteger_Disabled(t *testing.T) {
	spki := rsaSPKI(t, bigIntWithBits(20000))
	if got := findOversizedInteger(spki, 0); got != 0 {
		t.Errorf("got %d, want 0 when disabled", got)
	}
}

func TestFindOversizedInteger_DSAParameters(t *testing.T) {
	// DSA SubjectPublicKeyInfo with an oversized p in the AlgorithmIdentifier parameters.
	params, _ := asn1.Marshal(struct{ P, Q, G *big.Int }{bigIntWithBits(16392), bigIntWithBits(256), big.NewInt(2)})
	y, _ := asn1.Marshal(big.NewInt(12345))
	spki, err := asn1.Marshal(struct {
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue
		}{asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, asn1.RawValue{FullBytes: params}},
		PublicKey: asn1.BitString{Bytes: y, BitLength: len(y) * 8},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := findOversizedInteger(spki, 16384); got != 16392 {
		t.Errorf("got %d, want 16392", got)
	}
}

// berWrap returns a BER encoding of a constructed SEQUENCE around content, using
// either indefinite length or a non-minimal 8-byte definite length.
func berWrap(content []byte, indefinite bool) []byte {
	if indefinite {
		return append(append([]byte{0x30, 0x80}, content...), 0x00, 0x00)
	}
	out := []byte{0x30, 0x88}
	for i := 7; i >= 0; i-- {
		out = append(out, byte(uint64(len(content))>>(8*i)))
	}
	return append(out, content...)
}

func TestFindOversizedInteger_LenientEncodings(t *testing.T) {
	spki := rsaSPKI(t, bigIntWithBits(16400))
	for name, input := range map[string][]byte{
		"indefinite":   berWrap(spki, true),
		"non-minimal":  berWrap(spki, false),
		"nested mixed": berWrap(berWrap(spki, false), true),
		"high tag":     append([]byte{0xbf, 0x81, 0x00, 0x82, byte(len(spki) >> 8), byte(len(spki))}, spki...),
	} {
		if got := findOversizedInteger(input, 16384); got != 16400 {
			t.Errorf("%s: got %d, want 16400", name, got)
		}
	}
}

func TestFindOversizedInteger_OpaqueBitString(t *testing.T) {
	// A BIT STRING whose contents begin like a large INTEGER but do not parse
	// completely (e.g. random key material) must not be reported.
	integer, _ := asn1.Marshal(bigIntWithBits(16400))
	opaque := append(integer, 0xde, 0xad, 0xbe)
	bs, _ := asn1.Marshal(asn1.BitString{Bytes: opaque, BitLength: len(opaque) * 8})
	if got := findOversizedInteger(bs, 16384); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
	// The same contents in an OCTET STRING that parse completely must be reported.
	octets, _ := asn1.Marshal(integer)
	if got := findOversizedInteger(octets, 16384); got != 16400 {
		t.Errorf("OCTET STRING: got %d, want 16400", got)
	}
}

func TestFindOversizedInteger_DeepNesting(t *testing.T) {
	// Pathological nesting must neither recurse unboundedly nor panic.
	input := bytes.Repeat([]byte{0x30, 0x80}, 100000)
	_ = findOversizedInteger(input, 16384)
	input = []byte{0x02, 0x01, 0x01}
	for i := 0; i < 1000; i++ {
		input = berWrap(input, false)
	}
	if got := findOversizedInteger(input, 16384); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestFindOversizedInteger_Truncated(t *testing.T) {
	spki := rsaSPKI(t, bigIntWithBits(16400))
	for i := 0; i < len(spki); i += 97 {
		_ = findOversizedInteger(spki[:i], 16384)
	}
}

func TestIntegerBitLen(t *testing.T) {
	for _, tc := range []struct {
		content []byte
		want    int
	}{
		{nil, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x00, 0x00, 0x01, 0x00}, 9},
		{[]byte{0xff}, 0},
		{[]byte{0x80}, 7},
		{[]byte{0xff, 0xff, 0x7f, 0xff}, 16},
	} {
		if got := integerBitLen(tc.content); got != tc.want {
			t.Errorf("integerBitLen(%x) = %d, want %d", tc.content, got, tc.want)
		}
	}
}

func TestPOST_RejectsOversizedInteger(t *testing.T) {
	savedTimeout, savedMax := config.Config.Server.RequestTimeout, config.Config.Linter.MaxIntegerBits
	config.Config.Server.RequestTimeout, config.Config.Linter.MaxIntegerBits = 5*time.Second, 16384
	defer func() {
		config.Config.Server.RequestTimeout, config.Config.Linter.MaxIntegerBits = savedTimeout, savedMax
	}()

	for _, tc := range []struct {
		bits     int
		rejected bool
	}{
		{4096, false},
		{20000, true},
	} {
		cert := certWithPublicKey(t, &rsa.PublicKey{N: bigIntWithBits(tc.bits), E: 65537})
		var req fasthttp.Request
		req.Header.SetMethod(fasthttp.MethodPost)
		req.Header.SetContentType("application/pkix-cert")
		req.SetRequestURI("/lintcert?format=text")
		req.SetBody(cert)
		var ctx fasthttp.RequestCtx
		ctx.Init(&req, nil, nil)
		POST(&ctx, ENDPOINTSTRING_LINTCERT)
		body := string(ctx.Response.Body())
		if rejected := strings.Contains(body, "20000-bit INTEGER, which exceeds the 16384-bit limit"); rejected != tc.rejected {
			t.Errorf("%d-bit modulus: rejected = %t, want %t; body = %q", tc.bits, rejected, tc.rejected, body)
		} else if !tc.rejected && !strings.Contains(body, "Profile:") {
			t.Errorf("%d-bit modulus: linting did not proceed; body = %q", tc.bits, body)
		}
	}
}
