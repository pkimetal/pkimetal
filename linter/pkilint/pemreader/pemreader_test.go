package pemreader

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// request is one (profile_id, pem_data) pair yielded by read_pem_requests.
type request struct {
	ProfileID int
	PEMData   string
}

// runReader feeds wire into the Reader generator (executed by python3) and
// returns the yielded requests.  It skips the test if python3 is unavailable,
// and fails if the generator raises (e.g. an invalid profile).
func runReader(t *testing.T, wire string) []request {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	const driver = `
import sys, json
for profile_id, pem_data in read_pem_requests(sys.stdin):
	sys.stdout.write(json.dumps([profile_id, pem_data]) + "\n")
`
	cmd := exec.Command(python, "-c", Reader+driver)
	cmd.Stdin = strings.NewReader(wire)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("read_pem_requests failed: %v\nstderr: %s", err, stderr.String())
	}

	var requests []request
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var pair []json.RawMessage
		if err := json.Unmarshal([]byte(line), &pair); err != nil {
			t.Fatalf("failed to parse %q: %v", line, err)
		}
		var r request
		if err := json.Unmarshal(pair[0], &r.ProfileID); err != nil {
			t.Fatalf("failed to parse profile id from %q: %v", line, err)
		}
		if err := json.Unmarshal(pair[1], &r.PEMData); err != nil {
			t.Fatalf("failed to parse pem data from %q: %v", line, err)
		}
		requests = append(requests, r)
	}
	return requests
}

func assertRequests(t *testing.T, got, want []request) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d requests, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].ProfileID != want[i].ProfileID {
			t.Errorf("request %d: got profile id %d, want %d", i, got[i].ProfileID, want[i].ProfileID)
		}
		if got[i].PEMData != want[i].PEMData {
			t.Errorf("request %d: got pem data %q, want %q", i, got[i].PEMData, want[i].PEMData)
		}
	}
}

func TestReadPemRequests_MultipleRequestsAndAllSupportedTypes(t *testing.T) {
	want := []request{
		{3, "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"},
		{32, "-----BEGIN X509 CRL-----\nZGVm\n-----END X509 CRL-----\n"},
		{13, "-----BEGIN OCSP RESPONSE-----\nZ2hp\n-----END OCSP RESPONSE-----\n"},
	}
	var wire strings.Builder
	for _, r := range want {
		wire.WriteString(strconv.Itoa(r.ProfileID))
		wire.WriteString("\n")
		wire.WriteString(r.PEMData)
	}
	assertRequests(t, runReader(t, wire.String()), want)
}

func TestReadPemRequests_WhitespaceAndCRLFAreNormalized(t *testing.T) {
	wire := " 32 \r\n -----BEGIN X509 CRL----- \r\n" +
		"\tYWJj \r\n -----END X509 CRL----- \r\n"
	want := []request{{32, "-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----\n"}}
	assertRequests(t, runReader(t, wire), want)
}

func TestReadPemRequests_LargeRequestFollowedBySmallRequest(t *testing.T) {
	// Roughly 6 MiB of PEM, followed by another request on the same worker.
	large := "-----BEGIN X509 CRL-----\n" +
		strings.Repeat(strings.Repeat("A", 64)+"\n", 100000) +
		"-----END X509 CRL-----\n"
	small := "-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----\n"
	wire := "32\n" + large + "11\n" + small
	want := []request{{32, large}, {11, small}}
	assertRequests(t, runReader(t, wire), want)
}

func TestReadPemRequests_IncompleteInputIsNotDispatched(t *testing.T) {
	for _, wire := range []string{"", "32\n", "32\n-----BEGIN X509 CRL-----\nYWJj\n"} {
		if got := runReader(t, wire); len(got) != 0 {
			t.Errorf("wire %q: expected no requests, got %+v", wire, got)
		}
	}
}

func TestReadPemRequests_InvalidProfileIsRejected(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	const driver = `
import sys
list(read_pem_requests(sys.stdin))
`
	cmd := exec.Command(python, "-c", Reader+driver)
	cmd.Stdin = strings.NewReader("invalid\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected read_pem_requests to raise for an invalid profile id")
	}
	if !strings.Contains(stderr.String(), "ValueError") {
		t.Errorf("expected a ValueError, got stderr: %s", stderr.String())
	}
}
