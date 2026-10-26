package paranoid

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	"golang.org/x/crypto/ocsp"
)

var _ = func() bool {
	if PythonDir == "" {
		PythonDir = "."
	}
	return true
}()

func TestUnsupportedProfiles(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		enableCA, enableLeaf, enableCRL, enableOCSP := mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0
		t.Run(fmt.Sprintf("ca=%t/leaf=%t/crl=%t/ocsp=%t", enableCA, enableLeaf, enableCRL, enableOCSP), func(t *testing.T) {
			unsupported := unsupportedProfiles(enableCA, enableLeaf, enableCRL, enableOCSP)
			for id, profile := range linter.AllProfiles {
				var wantEnabled bool
				switch {
				case id == linter.AUTODETECT:
					wantEnabled = mask != 0
				case strings.HasSuffix(profile.Name, "_crl"), strings.HasSuffix(profile.Name, "_arl"):
					wantEnabled = enableCRL
				case strings.HasSuffix(profile.Name, "_ocspresponse"):
					wantEnabled = enableOCSP
				case strings.Contains(profile.Name, "_root"), strings.Contains(profile.Name, "_subordinate"), strings.Contains(profile.Name, "_cross_"):
					wantEnabled = enableCA
				default:
					wantEnabled = enableLeaf
				}
				if gotEnabled := !slices.Contains(unsupported, id); gotEnabled != wantEnabled {
					t.Errorf("%s enabled = %t, want %t", profile.Name, gotEnabled, wantEnabled)
				}
			}
		})
	}
}

func TestProfileRegistration(t *testing.T) {
	settings := config.Config.Linter.Paranoid
	t.Logf("CA=%t leaf=%t CRL=%t OCSP=%t", settings.EnableCACertificates, settings.EnableLeafCertificates, settings.EnableCRLs, settings.EnableOCSPResponses)
	unsupported := unsupportedProfiles(settings.EnableCACertificates, settings.EnableLeafCertificates, settings.EnableCRLs, settings.EnableOCSPResponses)
	var registered *linter.Linter
	for _, backend := range linter.Linters {
		if backend.Name == "paranoid" {
			registered = backend
			break
		}
	}
	if registered == nil {
		t.Fatal("Paranoid backend was not registered")
	}
	for id, profile := range linter.AllProfiles {
		wantUnsupported := slices.Contains(unsupported, id)
		if slices.Contains(registered.Unsupported, id) != wantUnsupported {
			t.Errorf("%s has incorrect dispatch eligibility", profile.Name)
		}
		advertised := slices.ContainsFunc(profile.Linters, func(name *string) bool { return *name == "paranoid" })
		if wantAdvertised := settings.NumProcesses > 0 && !wantUnsupported; advertised != wantAdvertised {
			t.Errorf("%s advertises Paranoid = %t, want %t", profile.Name, advertised, wantAdvertised)
		}
	}
}

func TestWorkerSyntax(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	_, _, _, args := (&Paranoid{}).StartInstance()
	command := exec.Command(python, "-c", "import sys; compile(sys.argv[1], '<worker>', 'exec')", args[1])
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid Python worker: %v\n%s", err, output)
	}
}

func TestProcessResult(t *testing.T) {
	result := (&Paranoid{}).ProcessResult(linter.LintingResult{Code: "paranoid.CheckROCA", Severity: linter.SEVERITY_ERROR})
	if result.Finding != "Paranoid detected a potential cryptographic weakness: CheckROCA" || result.Severity != linter.SEVERITY_ERROR {
		t.Fatalf("unexpected result: %+v", result)
	}
	fatal := linter.LintingResult{Finding: "Exception: malformed certificate", Severity: linter.SEVERITY_FATAL}
	if got := (&Paranoid{}).ProcessResult(fatal); got != fatal {
		t.Fatalf("fatal diagnostic changed: %+v", got)
	}
}

func TestWorkerIntegration(t *testing.T) {
	python := os.Getenv("PARANOID_PYTHON")
	if python == "" {
		t.Skip("set PARANOID_PYTHON to an interpreter with paranoid_crypto installed")
	}
	now := time.Now().UTC().Truncate(time.Second)
	curve := elliptic.P256()
	publicX, publicY := curve.ScalarBaseMult([]byte{1})
	weakKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: publicX, Y: publicY},
		D:         big.NewInt(1),
	}
	name := pkix.Name{CommonName: "Paranoid test"}
	makeCertificate := func(key crypto.Signer, subject pkix.Name) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               subject,
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		issuer := *template
		issuer.Subject = name
		der, err := x509.CreateCertificate(rand.Reader, template, &issuer, key.Public(), key)
		if err != nil {
			t.Fatalf("create certificate: %v", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		return certificate
	}
	certificate := makeCertificate(weakKey, name)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, certificate, weakKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	makeOCSP := func(embedded bool) []byte {
		t.Helper()
		response := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: certificate.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   now.Add(24 * time.Hour),
		}
		if embedded {
			response.Certificate = certificate
		}
		der, err := ocsp.CreateResponse(certificate, certificate, response, weakKey)
		if err != nil {
			t.Fatalf("create OCSP response: %v", err)
		}
		return der
	}
	tests := []struct {
		name          string
		pemType       string
		der           []byte
		wantCodes     []string
		absentCodes   []string
		exactCodes    bool
		requireFields bool
		fieldPrefix   string
	}{
		{
			name: "weak_ec_key_and_self_signed_signature", pemType: "CERTIFICATE", der: certificate.Raw,
			wantCodes: []string{"paranoid.CheckWeakECPrivateKey"}, absentCodes: []string{"signature_not_checked"},
			requireFields: true,
		},
		{
			name: "rsa_key", pemType: "CERTIFICATE", der: makeCertificate(rsaKey, name).Raw,
			wantCodes: []string{"paranoid.CheckSizes", "signature_not_checked"},
		},
		{
			name: "missing_issuer_key", pemType: "CERTIFICATE", der: makeCertificate(weakKey, pkix.Name{CommonName: "Leaf"}).Raw,
			wantCodes: []string{"signature_not_checked"},
		},
		{
			name: "unsupported_key", pemType: "CERTIFICATE", der: makeCertificate(edKey, name).Raw,
			wantCodes: []string{"unsupported_key"},
		},
		{
			name: "crl", pemType: "X509 CRL", der: crl,
			wantCodes: []string{"no_public_key", "signature_not_checked"}, exactCodes: true,
		},
		{
			name: "ocsp_with_signer", pemType: "OCSP RESPONSE", der: makeOCSP(true),
			wantCodes: []string{"paranoid.CheckWeakECPrivateKey"}, absentCodes: []string{"signature_not_checked"},
			fieldPrefix: "certificates[0]",
		},
		{
			name: "ocsp_without_signer", pemType: "OCSP RESPONSE", der: makeOCSP(false),
			wantCodes: []string{"no_public_key", "signature_not_checked"}, exactCodes: true,
		},
		{
			name: "unsuccessful_ocsp", pemType: "OCSP RESPONSE", der: ocsp.UnauthorizedErrorResponse,
			wantCodes: []string{"no_public_key", "signature_not_checked"}, exactCodes: true,
		},
	}
	var input strings.Builder
	input.WriteString("0\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")
	for _, test := range tests {
		fmt.Fprintf(&input, "0\n%s", pem.EncodeToMemory(&pem.Block{Type: test.pemType, Bytes: test.der}))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	_, _, _, args := (&Paranoid{}).StartInstance()
	command := exec.CommandContext(ctx, python, args...)
	command.Stdin = strings.NewReader(input.String())
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("Paranoid worker failed: %v\n%s", err, stderr.String())
	}
	scanner := bufio.NewScanner(&stdout)
	nextLine := func(t *testing.T) string {
		t.Helper()
		if !scanner.Scan() {
			t.Fatalf("unexpected end of worker output: %v\nstderr: %s", scanner.Err(), stderr.String())
		}
		return scanner.Text()
	}
	if got := nextLine(t); got != linter.PKIMETAL_READY {
		t.Fatalf("readiness signal = %q", got)
	}
	t.Run("protocol_and_error_recovery", func(t *testing.T) {
		if got := nextLine(t); !strings.HasPrefix(got, "F: Exception: ") {
			t.Errorf("malformed input response = %q", got)
		}
		if got := nextLine(t); got != linter.PKIMETAL_ENDOFRESULTS {
			t.Fatalf("end-of-results signal = %q", got)
		}
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line := nextLine(t)
			if got := nextLine(t); got != linter.PKIMETAL_ENDOFRESULTS {
				t.Fatalf("end-of-results signal = %q", got)
			}
			var report struct {
				Results []struct {
					NodePath string `json:"node_path"`
					Findings []struct {
						Code string `json:"code"`
					} `json:"finding_descriptions"`
				} `json:"results"`
			}
			if err := json.Unmarshal([]byte(line), &report); err != nil {
				t.Fatalf("decode worker results: %v\n%s", err, line)
			}
			var codes []string
			foundPrefix := false
			for _, result := range report.Results {
				if test.requireFields && result.NodePath == "" {
					t.Error("finding has no field path")
				}
				foundPrefix = foundPrefix || strings.HasPrefix(result.NodePath, test.fieldPrefix)
				for _, finding := range result.Findings {
					codes = append(codes, finding.Code)
				}
			}
			for _, code := range test.wantCodes {
				if !slices.Contains(codes, code) {
					t.Errorf("missing %s in %v", code, codes)
				}
			}
			for _, code := range test.absentCodes {
				if slices.Contains(codes, code) {
					t.Errorf("unexpected %s in %v", code, codes)
				}
			}
			if test.exactCodes && !slices.Equal(codes, test.wantCodes) {
				t.Errorf("codes = %v, want %v", codes, test.wantCodes)
			}
			if test.fieldPrefix != "" && !foundPrefix {
				t.Errorf("no field path starts with %q", test.fieldPrefix)
			}
		})
	}
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatalf("unexpected remaining worker output: %q (%v)", scanner.Text(), scanner.Err())
	}
}
