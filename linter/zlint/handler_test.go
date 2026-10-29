package zlint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/linter"

	"golang.org/x/crypto/ocsp"
)

func testCRLDER(t *testing.T, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	issuer := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             thisUpdate.Add(-time.Hour),
		NotAfter:              nextUpdate.Add(time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	crl := &cryptox509.RevocationList{
		SignatureAlgorithm: cryptox509.SHA256WithRSA,
		Number:             big.NewInt(1),
		ThisUpdate:         thisUpdate,
		NextUpdate:         nextUpdate,
	}
	der, err := cryptox509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatalf("failed to generate test CRL: %v", err)
	}
	return der
}

func hasFinding(results []linter.LintingResult, code string) bool {
	for _, result := range results {
		if result.Code == code {
			return true
		}
	}
	return false
}

func TestTBRCRLUsesSubscriberCRLNextUpdateLimit(t *testing.T) {
	thisUpdate := time.Date(2026, time.June, 24, 13, 0, 0, 0, time.UTC)

	validCRLResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 0, 9)),
		ProfileId:    linter.TBR_CRL,
	})
	if hasFinding(validCRLResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL reported nextUpdate limit violation for a 9-day subscriber CRL")
	}

	invalidCRLResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 0, 11)),
		ProfileId:    linter.TBR_CRL,
	})
	if !hasFinding(invalidCRLResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL did not report nextUpdate limit violation for an 11-day subscriber CRL")
	}
}

func TestTBRARLUsesCACRLNextUpdateLimit(t *testing.T) {
	thisUpdate := time.Date(2026, time.June, 24, 13, 0, 0, 0, time.UTC)
	crlDER := testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 11, 0))

	crlResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: crlDER,
		ProfileId:    linter.TBR_CRL,
	})
	if !hasFinding(crlResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL did not report subscriber nextUpdate limit violation")
	}

	arlResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: crlDER,
		ProfileId:    linter.TBR_ARL,
	})
	if hasFinding(arlResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR ARL reported subscriber nextUpdate limit violation")
	}
}

func TestTBROCSPResponseRunsCABFLints(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	thisUpdate := time.Date(2026, time.June, 24, 13, 0, 0, 0, time.UTC)
	issuerDER, err := cryptox509.CreateCertificate(rand.Reader, &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             thisUpdate.Add(-time.Hour),
		NotAfter:              thisUpdate.AddDate(1, 0, 0),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, &cryptox509.Certificate{Subject: pkix.Name{CommonName: "test issuer"}}, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to generate test issuer: %v", err)
	}
	issuer, err := cryptox509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("failed to parse test issuer: %v", err)
	}

	// P-384 key with ECDSA-SHA256 violates the TLS BRs' signature AlgorithmIdentifier rules.
	ocspDER, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		Status:             ocsp.Good,
		SerialNumber:       big.NewInt(2),
		ThisUpdate:         thisUpdate,
		NextUpdate:         thisUpdate.AddDate(0, 0, 4),
		SignatureAlgorithm: cryptox509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatalf("failed to generate test OCSP response: %v", err)
	}

	rfcResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: ocspDER,
		ProfileId:    linter.RFC6960_OCSPRESPONSE,
	})
	if hasFinding(rfcResults, "e_ocsp_ecdsa_signature_encoding_correct") {
		t.Fatal("RFC6960 OCSP response profile ran a CABForum lint")
	}

	tbrResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: ocspDER,
		ProfileId:    linter.TBR_OCSPRESPONSE,
	})
	if !hasFinding(tbrResults, "e_ocsp_ecdsa_signature_encoding_correct") {
		t.Fatal("TBR OCSP response profile did not report ECDSA signature encoding violation")
	}
}
