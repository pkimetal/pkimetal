package linter

import (
	"context"
	"testing"
)

func TestParseResultToken_EndOfResults(t *testing.T) {
	results, end, err := parseResultToken("pkilint", PKIMETAL_ENDOFRESULTS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !end {
		t.Error("expected end=true for the end-of-results sentinel")
	}
	if results != nil {
		t.Errorf("expected no results, got %v", results)
	}
}

func TestParseResultToken_LegacySeverities(t *testing.T) {
	cases := map[string]SeverityLevel{
		"D: debug msg":   SEVERITY_DEBUG,
		"I: info msg":    SEVERITY_INFO,
		"N: notice msg":  SEVERITY_NOTICE,
		"W: warning msg": SEVERITY_WARNING,
		"E: error msg":   SEVERITY_ERROR,
		"B: bug msg":     SEVERITY_BUG,
		"F: fatal msg":   SEVERITY_FATAL,
	}
	for token, wantSeverity := range cases {
		results, end, err := parseResultToken("certlint", token)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", token, err)
			continue
		}
		if end {
			t.Errorf("%q: unexpected end=true", token)
		}
		if len(results) != 1 {
			t.Errorf("%q: expected 1 result, got %d", token, len(results))
			continue
		}
		if results[0].Severity != wantSeverity {
			t.Errorf("%q: got severity %d, want %d", token, results[0].Severity, wantSeverity)
		}
		if results[0].LinterName != "certlint" {
			t.Errorf("%q: got linter name %q, want certlint", token, results[0].LinterName)
		}
		if results[0].Finding != token[3:] {
			t.Errorf("%q: got finding %q, want %q", token, results[0].Finding, token[3:])
		}
	}
}

func TestParseResultToken_LegacyErrors(t *testing.T) {
	for _, token := range []string{"E: ", "E:x", "Z: unknown severity"} {
		if _, _, err := parseResultToken("certlint", token); err == nil {
			t.Errorf("%q: expected an error, got nil", token)
		}
	}
}

func TestParseResultToken_JSON(t *testing.T) {
	token := `{"results":[{"node_path":"tbsCertificate.extensions","validator":"v","finding_descriptions":[{"severity":"ERROR","code":"cabf.some_finding","message":"m"}]}]}`
	results, end, err := parseResultToken("pkilint", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if end {
		t.Error("unexpected end=true")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.LinterName != "pkilint" || r.Finding != "cabf.some_finding" || r.Code != "cabf.some_finding" || r.Field != "tbsCertificate.extensions" {
		t.Errorf("unexpected result: %+v", r)
	}
	if r.Severity != SEVERITY_ERROR {
		t.Errorf("got severity %d, want %d", r.Severity, SEVERITY_ERROR)
	}
}

func TestParseResultToken_JSONMultiple(t *testing.T) {
	token := `{"results":[{"node_path":"a","finding_descriptions":[{"severity":"WARNING","code":"c1"},{"severity":"NOTICE","code":"c2"}]},{"node_path":"b","finding_descriptions":[{"severity":"INFO","code":"c3"}]}]}`
	results, _, err := parseResultToken("pkilint", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestParseResultToken_JSONEmptyResults(t *testing.T) {
	results, end, err := parseResultToken("pkilint", `{"results":[]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if end || len(results) != 0 {
		t.Errorf("expected no results and end=false, got end=%v results=%v", end, results)
	}
}

func TestParseResultToken_Malformed(t *testing.T) {
	// Empty and single-character tokens must not panic (regression: token[1]
	// used to be indexed before the length was checked).
	for _, token := range []string{"", "{", "x", "hello", "{bad json"} {
		if _, _, err := parseResultToken("pkilint", token); err == nil {
			t.Errorf("%q: expected an error, got nil", token)
		}
	}
}

func TestSendResult_DeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Deadline already exceeded.
	lreq := &LintingRequest{
		Ctx:         ctx,
		RespChannel: make(chan LintingResult), // Unbuffered, no reader.
	}
	var lin LinterInstance
	if lin.sendResult(lreq, LintingResult{Finding: "x"}) {
		t.Error("sendResult should return false when the request deadline is exceeded")
	}
}

func TestSendResult_Delivered(t *testing.T) {
	lreq := &LintingRequest{
		Ctx:         context.Background(),
		RespChannel: make(chan LintingResult, 1),
	}
	var lin LinterInstance
	if !lin.sendResult(lreq, LintingResult{Finding: "x"}) {
		t.Fatal("sendResult should return true when the result is delivered")
	}
	if got := <-lreq.RespChannel; got.Finding != "x" {
		t.Errorf("got finding %q, want x", got.Finding)
	}
}
