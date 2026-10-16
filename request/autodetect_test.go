package request

import (
	"net/url"
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

func TestProfileMatchesEndpoint(t *testing.T) {
	cases := []struct {
		endpoint Endpoint
		profile  string
		want     bool
	}{
		{ENDPOINT_LINTCERT, "rfc5280_leaf", true},
		{ENDPOINT_LINTTBSCERT, "tbr_leaf_tlsserver_dv", true},
		{ENDPOINT_LINTCERT, "rfc5280_crl", false},
		{ENDPOINT_LINTTBSCERT, "rfc6960_ocspresponse", false},
		{ENDPOINT_LINTCRL, "rfc5280_crl", true},
		{ENDPOINT_LINTTBSCRL, "tbr_arl", true},
		{ENDPOINT_LINTCRL, "rfc5280_leaf", false},
		{ENDPOINT_LINTTBSCRL, "rfc5280_leaf", false},
		{ENDPOINT_LINTTBSCRL, "rfc6960_ocspresponse", false},
		{ENDPOINT_LINTOCSP, "rfc6960_ocspresponse", true},
		{ENDPOINT_LINTTBSOCSP, "rfc5280_crl", false},
		{ENDPOINT_LINTOCSP, "rfc5280_root", false},
	}
	for _, c := range cases {
		ri := RequestInfo{endpoint: c.endpoint}
		if !ri.GetProfile(c.profile) {
			t.Fatalf("%s: GetProfile returned false", c.profile)
		}
		if got := ri.ProfileMatchesEndpoint(); got != c.want {
			t.Errorf("endpoint %d, profile %s: got %v, want %v", c.endpoint, c.profile, got, c.want)
		}
	}
}

// Regression test for https://github.com/pkimetal/pkimetal/issues/2057.
func TestProfileMatchesEndpoint_TBSCRLWithCertificateProfile(t *testing.T) {
	form := url.Values{}
	form.Set("b64input", "MIGJAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0EXDTI2MTAxNjAwMDAwMFoXDTI2MTAyMzAwMDAwMFowFTATAgISNBcNMjYxMDE2MDAwMDAwWqAvMC0wCgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAUJFxUjU16tdpwXm84Ol0wQ5oJ20U=")
	ctx := newPostCtx("application/x-www-form-urlencoded", []byte(form.Encode()))

	ri := RequestInfo{endpoint: ENDPOINT_LINTTBSCRL}
	if err := ri.GetInput(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ri.GetProfile("rfc5280_leaf") {
		t.Fatal("GetProfile returned false")
	}
	if ri.ProfileMatchesEndpoint() {
		t.Error("a certificate profile must not be accepted for a TBSCertList")
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
