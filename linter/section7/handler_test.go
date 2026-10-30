package section7

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"

	"github.com/cps-kit/section7"
)

const profileYAML = `profile:
  name: Test CPS
  recognized_by:
    policy_oid: 1.2.3.4
requirements:
  version: v3
  signature_algorithm:
    allowed: [id-Ed25519]
  issuer:
    attributes:
      common_name:
        required: true
  validity:
    maximum_days: 30
  subject:
    attributes:
      common_name:
        required: true
  public_key:
    algorithms:
      - name: id-Ed25519
  extensions:
    certificate_policies:
      required: true
      critical: false
      required_values: [1.2.3.4]
`

func writeProfile(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testProfiles(t *testing.T) *section7.ProfileSet {
	t.Helper()
	directory := t.TempDir()
	writeProfile(t, directory, "test.yaml", profileYAML)
	loaded, err := section7.LoadProfileSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func testCertificate(t *testing.T, precertificate bool) *x509.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := x509.ParseOID("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, time.October, 30, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    start,
		NotAfter:     start.Add(24 * time.Hour),
		Policies:     []x509.OID{policy},
	}
	if precertificate {
		template.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, Critical: true, Value: []byte{5, 0},
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestLoadProfiles(t *testing.T) {
	directory := t.TempDir()
	writeProfile(t, directory, "_base.yaml", profileYAML)
	writeProfile(t, directory, "b.yml", "extends: _base.yaml\nprofile:\n  name: B\n  recognized_by:\n    policy_oid: 1.2.3.5\n")
	writeProfile(t, directory, "a.yaml", "extends: _base.yaml\nprofile:\n  name: A\n")
	writeProfile(t, directory, "ignored.txt", "not a profile")
	loaded, err := section7.LoadProfileSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	path, selected, finding := loaded.SelectProfile(testCertificate(t, false))
	if finding != nil || path != filepath.Join(directory, "a.yaml") || selected.Profile.Profile.Name != "A" {
		t.Fatalf("expected inherited profile A, got path=%q profile=%+v finding=%v", path, selected, finding)
	}
}

func TestLoadProfilesRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{name: "empty directory"},
		{name: "malformed YAML", contents: "profile: ["},
		{name: "invalid requirements", contents: "profile:\n  name: Invalid\nrequirements: {}\n"},
		{name: "unknown key", contents: profileYAML + "  unknown_requirement: true\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if test.contents != "" {
				writeProfile(t, directory, "test.yaml", test.contents)
			}
			if _, err := section7.LoadProfileSet(directory); err == nil {
				t.Fatal("expected profile loading to fail")
			}
		})
	}
	for _, directory := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if _, err := section7.LoadProfileSet(directory); err == nil {
			t.Fatalf("expected profile loading to fail for %q", directory)
		}
	}
	t.Run("fragments only", func(t *testing.T) {
		directory := t.TempDir()
		writeProfile(t, directory, "_base.yaml", profileYAML)
		writeProfile(t, directory, "ignored.txt", "not a profile")
		if _, err := section7.LoadProfileSet(directory); err == nil {
			t.Fatal("expected profile loading to reject a directory without standalone profiles")
		}
	})
}

func TestHandleRequestConvertsFindings(t *testing.T) {
	previous := profiles
	profiles = testProfiles(t)
	t.Cleanup(func() { profiles = previous })
	cert := testCertificate(t, true)
	results := (&Section7{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{DecodedInput: cert.Raw})
	path, findings := profiles.LintCertificate(cert)
	if len(results) != len(findings) {
		t.Fatalf("expected %d findings, got %d", len(findings), len(results))
	}
	seen := map[linter.SeverityLevel]bool{}
	for index, result := range results {
		if result.Code != findings[index].RuleID || result.Finding != findings[index].Message || result.Field != path {
			t.Fatalf("finding metadata was lost: %+v", result)
		}
		seen[result.Severity] = true
	}
	for _, severity := range []linter.SeverityLevel{linter.SEVERITY_ERROR, linter.SEVERITY_WARNING, linter.SEVERITY_INFO} {
		if !seen[severity] {
			t.Errorf("missing severity %v in %+v", severity, results)
		}
	}
	bad := (&Section7{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{DecodedInput: []byte("not DER")})
	if len(bad) != 1 || bad[0].Severity != linter.SEVERITY_FATAL {
		t.Fatalf("expected fatal parse finding, got %+v", bad)
	}
}

func TestProfileSelection(t *testing.T) {
	cert := testCertificate(t, false)
	for _, test := range []struct {
		name    string
		policy  string
		version time.Time
		code    string
	}{
		{name: "unversioned", policy: "1.2.3.4"},
		{name: "older version", policy: "1.2.3.4", version: cert.NotBefore.Add(-time.Second)},
		{name: "exact version", policy: "1.2.3.4", version: cert.NotBefore},
		{name: "future version", policy: "1.2.3.4", version: cert.NotBefore.Add(time.Second), code: "PROFILE-TOONEW"},
		{name: "unmatched", policy: "1.2.3.5", code: "PROFILE-NOMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeProfile(t, directory, "_base.yaml", profileYAML)
			contents := fmt.Sprintf("extends: _base.yaml\nprofile:\n  recognized_by:\n    policy_oid: %s\n", test.policy)
			if !test.version.IsZero() {
				contents += "  version: " + test.version.Format(time.RFC3339) + "\n"
			}
			writeProfile(t, directory, "test.yaml", contents)
			candidates, err := section7.LoadProfileSet(directory)
			if err != nil {
				t.Fatal(err)
			}
			results := lintCertificate(context.Background(), cert, candidates)
			if test.code != "" {
				if len(results) != 1 || results[0].Code != test.code || results[0].Severity != linter.SEVERITY_ERROR || results[0].Field != "" {
					t.Fatalf("expected %s error, got %+v", test.code, results)
				}
				return
			}
			if len(results) == 0 {
				t.Fatal("expected findings for matching profile")
			}
			for _, result := range results {
				if result.Severity != linter.SEVERITY_INFO || result.Field != filepath.Join(directory, "test.yaml") {
					t.Errorf("valid certificate produced unexpected finding: %+v", result)
				}
			}
		})
	}
	cert.PolicyIdentifiers = nil
	cert.Policies = nil
	results := lintCertificate(context.Background(), cert, testProfiles(t))
	if len(results) != 1 || results[0].Code != "PROFILE-NOMATCH" || !strings.Contains(results[0].Finding, "found: none") {
		t.Fatalf("expected no-policy finding, got %+v", results)
	}
}

func TestProfileSetSelectsOneLatestProfile(t *testing.T) {
	cert := testCertificate(t, false)
	directory := t.TempDir()
	writeProfile(t, directory, "_base.yaml", profileYAML)
	writeProfile(t, directory, "unversioned.yaml", "extends: _base.yaml\n")
	for _, profile := range []struct {
		name    string
		version time.Time
	}{
		{name: "older.yaml", version: cert.NotBefore.Add(-time.Hour)},
		{name: "latest.yaml", version: cert.NotBefore},
		{name: "future.yaml", version: cert.NotBefore.Add(time.Hour)},
	} {
		writeProfile(t, directory, profile.name, "extends: _base.yaml\nprofile:\n  version: "+profile.version.Format(time.RFC3339)+"\n")
	}
	candidates, err := section7.LoadProfileSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	results := lintCertificate(context.Background(), cert, candidates)
	if len(results) == 0 {
		t.Fatal("expected findings from the selected profile")
	}
	for _, result := range results {
		if result.Field != filepath.Join(directory, "latest.yaml") {
			t.Fatalf("expected only the latest eligible profile, got %+v", result)
		}
	}
	writeProfile(t, directory, "duplicate.yaml", "extends: latest.yaml\n")
	candidates, err = section7.LoadProfileSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	results = lintCertificate(context.Background(), cert, candidates)
	if len(results) != 1 || results[0].Code != "PROFILE-AMBIGUOUS" || results[0].Severity != linter.SEVERITY_ERROR || results[0].Field != "" {
		t.Fatalf("expected an ambiguity error without linting any profile, got %+v", results)
	}
}

func TestProfileSetReusedWithoutReadingFiles(t *testing.T) {
	directory := t.TempDir()
	writeProfile(t, directory, "test.yaml", profileYAML)
	candidates, err := section7.LoadProfileSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCertificate(t, false)
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	for request := 0; request < 4; request++ {
		t.Run(fmt.Sprintf("request%d", request), func(t *testing.T) {
			t.Parallel()
			results := lintCertificate(context.Background(), cert, candidates)
			if len(results) == 0 {
				t.Fatal("expected findings from the startup-loaded profile set")
			}
			for _, result := range results {
				if result.Field != filepath.Join(directory, "test.yaml") || result.Severity != linter.SEVERITY_INFO {
					t.Fatalf("could not reuse loaded profile: %+v", result)
				}
			}
		})
	}
}

func TestStartupConfiguration(t *testing.T) {
	if expected := os.Getenv("SECTION7_STARTUP_TEST"); expected != "" {
		for _, backend := range linter.Linters {
			if backend.Name != "section7" {
				continue
			}
			if fmt.Sprint(backend.NumInstances) != expected || (profiles != nil) != (backend.NumInstances > 0) {
				t.Fatalf("configuration was not applied: instances=%d profiles=%v", backend.NumInstances, profiles)
			}
			return
		}
		t.Fatal("section7 was not registered")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	writeProfile(t, directory, "test.yaml", profileYAML)
	prefix := strings.ReplaceAll(strings.ToUpper(config.ApplicationNamespace), ".", "_") + "_LINTER_SECTION7_"
	for _, test := range []struct {
		name      string
		instances string
		directory string
		wantError string
	}{
		{name: "disabled", instances: "0"},
		{name: "enabled", instances: "1", directory: directory},
		{name: "missing directory setting", instances: "1", wantError: "no profile directory given"},
		{name: "empty directory", instances: "1", directory: t.TempDir(), wantError: "no profiles in"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestStartupConfiguration$")
			command.Env = append(os.Environ(), "SECTION7_STARTUP_TEST="+test.instances,
				prefix+"NUMGOROUTINES="+test.instances, prefix+"PROFILESDIR="+test.directory)
			output, err := command.CombinedOutput()
			if test.wantError != "" {
				if err == nil || !strings.Contains(string(output), test.wantError) {
					t.Fatalf("expected startup error %q, got %v: %s", test.wantError, err, output)
				}
			} else if err != nil {
				t.Fatalf("startup failed: %v: %s", err, output)
			}
		})
	}
}
