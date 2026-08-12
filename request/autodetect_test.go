package request

import (
	"testing"

	"github.com/pkimetal/pkimetal/linter"

	"github.com/zmap/zcrypto/x509"
)

func TestGetProfile_Explicit(t *testing.T) {
	var ri RequestInfo
	if !ri.GetProfile("rfc5280_leaf") || ri.profileId != linter.RFC5280_LEAF {
		t.Errorf("rfc5280_leaf: got profileId %d", ri.profileId)
	}
	if ri.GetProfile("this_profile_does_not_exist") {
		t.Error("expected false for an unknown profile name")
	}
}

func TestGetProfile_OCSPAutodetect(t *testing.T) {
	for _, ep := range []Endpoint{ENDPOINT_LINTOCSP, ENDPOINT_LINTTBSOCSP} {
		ri := RequestInfo{endpoint: ep}
		if !ri.GetProfile("") || ri.profileId != linter.RFC6960_OCSPRESPONSE {
			t.Errorf("endpoint %d: got profileId %d, want RFC6960_OCSPRESPONSE", ep, ri.profileId)
		}
	}
}

func TestGetProfile_CRLAutodetectDefault(t *testing.T) {
	// An unparseable CRL falls back to the RFC5280 CRL profile.
	ri := RequestInfo{endpoint: ENDPOINT_LINTCRL, decodedInput: []byte("not a CRL")}
	if !ri.GetProfile("") || ri.profileId != linter.RFC5280_CRL {
		t.Errorf("got profileId %d, want RFC5280_CRL", ri.profileId)
	}
}

// certificateFixtures maps each certificate fixture to its expected auto-detected
// profile and whether it is a precertificate (i.e. carries the CT precertificate
// poison extension).
var certificateFixtures = []struct {
	file    string
	profile string
	precert bool
}{
	{"tls_ov_certificate.crt", "tbr_leaf_tlsserver_ov", false},
	{"tls_ov_precertificate.crt", "tbr_leaf_tlsserver_ov_precertificate", true},
	{"codesigning_ev.crt", "csbr_leaf_codesigning_ev", false},
	{"codesigning_ov.crt", "csbr_leaf_codesigning_ov", false},
	{"docsigning.crt", "rfc5280_leaf_documentsigning", false},
	{"pdf_signing.crt", "rfc5280_leaf_smime", false},
	{"qwac-l_certificate.crt", "etsi_leaf_tlsserver_qevcpweidas", false},
	{"qwac-l_precertificate.crt", "etsi_leaf_tlsserver_qevcpweidas_precertificate", true},
	{"smime_sv.crt", "sbr_leaf_smime_sv_multipurpose", false},
	{"cmc_certificate.crt", "bimigroup_leaf_commonmark", false},
	{"cmc_precertificate.crt", "bimigroup_leaf_commonmark_precertificate", true},
	{"vmc_certificate.crt", "bimigroup_leaf_verifiedmark", false},
	{"vmc_precertificate.crt", "bimigroup_leaf_verifiedmark_precertificate", true},
}

func TestGetProfile_CertificateAutodetect(t *testing.T) {
	for _, tc := range certificateFixtures {
		t.Run(tc.file, func(t *testing.T) {
			der := testcaseDER(t, tc.file)
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parsing %s: %v", tc.file, err)
			}
			ri := RequestInfo{endpoint: ENDPOINT_LINTCERT, decodedInput: der, cert: cert}
			if !ri.GetProfile("") {
				t.Fatal("GetProfile returned false")
			}

			// Autodetection must always resolve to a concrete profile.
			if ri.profileId == linter.AUTODETECT || ri.profileId < 0 {
				t.Fatalf("autodetection did not resolve: profileId=%d", ri.profileId)
			}
			profile, ok := linter.AllProfiles[ri.profileId]
			if !ok {
				t.Fatalf("resolved to an unknown profile id %d", ri.profileId)
			}
			if profile.Name != tc.profile {
				t.Errorf("got profile %q, want %q", profile.Name, tc.profile)
			}

			// The poison-extension detection must agree with the expected profile.
			if got := hasPoisonExtension(cert); got != tc.precert {
				t.Errorf("poison extension presence = %v, want %v", got, tc.precert)
			}
		})
	}
}

func hasPoisonExtension(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtension_PrecertificatePoison) {
			return true
		}
	}
	return false
}
