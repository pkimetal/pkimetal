package request

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestSendJSONResponse_Empty(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if status := sendJSONResponse(ctx, nil); status != fasthttp.StatusOK {
		t.Errorf("got status %d, want %d", status, fasthttp.StatusOK)
	}
	if body := string(ctx.Response.Body()); body != "[]" {
		t.Errorf("got body %q, want []", body)
	}
	if ct := string(ctx.Response.Header.ContentType()); !strings.Contains(ct, "application/json") {
		t.Errorf("got content type %q, want application/json", ct)
	}
}

func TestSendJSONResponse_RoundTrip(t *testing.T) {
	want := []LintResult{
		{Linter: "pkimetal", Finding: "Profile: rfc5280_leaf", Severity: "meta"},
		{Linter: "zlint", Finding: "e_finding", Field: "extensions", Code: "e_finding", Severity: "error"},
	}
	ctx := &fasthttp.RequestCtx{}
	sendJSONResponse(ctx, want)

	var got []LintResult
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSendJSONResponse_OmitsEmptyFieldAndCode(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	sendJSONResponse(ctx, []LintResult{{Linter: "zlint", Finding: "x", Severity: "info"}})
	body := string(ctx.Response.Body())
	if strings.Contains(body, "\"Field\"") || strings.Contains(body, "\"Code\"") {
		t.Errorf("expected empty Field/Code to be omitted, got %q", body)
	}
}

func TestSendTEXTResponse(t *testing.T) {
	results := []LintResult{
		{Linter: "zlint", Finding: "e_finding", Severity: "error"},
		{Linter: "pkilint", Finding: "w_finding", Field: "a.b", Severity: "warning"},
	}
	ctx := &fasthttp.RequestCtx{}
	if status := sendTEXTResponse(ctx, results); status != fasthttp.StatusOK {
		t.Errorf("got status %d, want %d", status, fasthttp.StatusOK)
	}
	want := "zlint\tERROR\te_finding\n" + "pkilint\tWARNING\tw_finding [a.b]\n"
	if body := string(ctx.Response.Body()); body != want {
		t.Errorf("got body %q, want %q", body, want)
	}
	if ct := string(ctx.Response.Header.ContentType()); !strings.Contains(ct, "text/plain") {
		t.Errorf("got content type %q, want text/plain", ct)
	}
}

func TestSendHTMLResponse_Empty(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if status := sendHTMLResponse(ctx, nil); status != fasthttp.StatusOK {
		t.Errorf("got status %d, want %d", status, fasthttp.StatusOK)
	}
	body := string(ctx.Response.Body())
	if !strings.Contains(body, "No findings") {
		t.Errorf("expected 'No findings' in empty HTML response, got %q", body)
	}
	if ct := string(ctx.Response.Header.ContentType()); !strings.Contains(ct, "text/html") {
		t.Errorf("got content type %q, want text/html", ct)
	}
}

func TestSendHTMLResponse_NonEmpty(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	sendHTMLResponse(ctx, []LintResult{{Linter: "zlint", Finding: "e_finding", Field: "ext", Code: "code1", Severity: "error"}})
	body := string(ctx.Response.Body())
	for _, want := range []string{"zlint", "ERROR", "e_finding", "ext", "code1"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in HTML response", want)
		}
	}
}
