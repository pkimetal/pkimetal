package ftfy

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeFtfyInput(t *testing.T) {
	input := "a\nb\rc\u0085d\u2028e\u2029f\xff"
	want := "a b c d e f\uFFFD"
	if got := sanitizeFtfyInput(input); got != want {
		t.Errorf("sanitizeFtfyInput() = %q, want %q", got, want)
	}
}

func TestFtfyInputIssues(t *testing.T) {
	tests := []struct {
		name                 string
		input                string
		invalidUTF8          bool
		replacementCharacter bool
		lineSeparators       []string
	}{
		{name: "invalid UTF-8", input: "\xff", invalidUTF8: true},
		{name: "literal replacement character", input: "\uFFFD", replacementCharacter: true},
		{name: "both", input: "\xff\uFFFD", invalidUTF8: true, replacementCharacter: true},
		{name: "valid text", input: "café"},
		{
			name:           "line separators",
			input:          "a\nb\rc\u0085d\u2028e\u2029f\u2028",
			lineSeparators: []string{"U+000A", "U+000D", "U+0085", "U+2028", "U+2029"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidUTF8, replacementCharacter, lineSeparators := ftfyInputIssues(tt.input)
			if invalidUTF8 != tt.invalidUTF8 || replacementCharacter != tt.replacementCharacter || !reflect.DeepEqual(lineSeparators, tt.lineSeparators) {
				t.Errorf("ftfyInputIssues() = (%t, %t, %v), want (%t, %t, %v)", invalidUTF8, replacementCharacter, lineSeparators, tt.invalidUTF8, tt.replacementCharacter, tt.lineSeparators)
			}
		})
	}
}

func TestParseFtfyResponse(t *testing.T) {
	want := "line one\nline two"
	line := "17\t" + base64.StdEncoding.EncodeToString([]byte(want))

	got, err := parseFtfyResponse(line, "17")
	if err != nil {
		t.Fatalf("parseFtfyResponse() error = %v", err)
	}
	if got != want {
		t.Errorf("parseFtfyResponse() = %q, want %q", got, want)
	}
}

func TestParseFtfyResponseRejectsWrongRequest(t *testing.T) {
	line := "16\t" + base64.StdEncoding.EncodeToString([]byte("previous request"))
	if _, err := parseFtfyResponse(line, "17"); err == nil {
		t.Fatal("parseFtfyResponse() accepted a response for a different request")
	}
}

func TestParseFtfyResponseRejectsMalformedOutput(t *testing.T) {
	for _, line := range []string{"17\tnot-base64!", "17\t//79", "malformed"} {
		if _, err := parseFtfyResponse(line, "17"); err == nil {
			t.Errorf("parseFtfyResponse(%q) returned no error", line)
		}
	}
}

func TestSanitizedInputDoesNotContainLineSeparators(t *testing.T) {
	got := sanitizeFtfyInput("a\nb\rc\u0085d\u2028e\u2029f")
	if strings.ContainsAny(got, "\n\r") || strings.ContainsRune(got, '\u0085') || strings.ContainsRune(got, '\u2028') || strings.ContainsRune(got, '\u2029') {
		t.Errorf("sanitized input still contains a line separator: %q", got)
	}
}
