package certlint

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/linter"
)

// stubCertlint is a minimal stand-in for the certlint library, whose linting
// raises on demand.
const stubCertlint = `module CertLint
	VERSION = "stub"

	def self.recurse
		recurse
	end

	module PEMLint
		def self.lint(pem, type)
			CertLint.recurse if pem.include?("STACK")
			raise ArgumentError, "multi\nline\tmessage" if pem.include?("ARG")
			raise ArgumentError, "x" * 100000 if pem.include?("HUGE")
			raise "\xff invalid UTF-8".dup.force_encoding("UTF-8") if pem.include?("UTF8")
			raise SystemExit if pem.include?("EXIT")
			[[], pem]
		end
	end

	module CABLint
		def self.lint(der)
			["W: cablint"]
		end
	end

	def self.lint(der)
		["W: certlint"]
	end
end
`

func runWorker(t *testing.T, bodies ...string) (string, error) {
	t.Helper()
	ruby, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib", "certlint.rb"), []byte(stubCertlint), 0o644); err != nil {
		t.Fatal(err)
	}

	var input strings.Builder
	for _, body := range bodies {
		input.WriteString("0\n-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n")
	}
	_, _, _, args := (&Certlint{}).StartInstance()
	cmd := exec.Command(ruby, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	return string(out), err
}

func TestWorker_ReportsExceptionsAndKeepsServing(t *testing.T) {
	out, err := runWorker(t, "STACK", "ARG", "HUGE", "UTF8", "OK")
	if err != nil {
		t.Fatalf("worker exited with error: %v; output = %q", err, out)
	}

	responses := strings.Split(strings.TrimSuffix(out, linter.PKIMETAL_ENDOFRESULTS+"\n"), linter.PKIMETAL_ENDOFRESULTS+"\n")
	if len(responses) != 5 {
		t.Fatalf("got %d responses, want 5; output = %q", len(responses), out)
	}
	for i, want := range []string{
		"F: Exception: SystemStackError: ",
		"F: Exception: ArgumentError: multi line message\n",
		"F: Exception: ArgumentError: xxx",
		"F: Exception: RuntimeError: ",
		"W: certlint\n",
	} {
		if !strings.HasPrefix(responses[i], want) {
			t.Errorf("response %d = %q, want prefix %q", i, responses[i], want)
		}
		if lines := strings.Count(responses[i], "\n"); lines != 1 {
			t.Errorf("response %d has %d lines, want 1", i, lines)
		}
		if len(responses[i]) > 1025 {
			t.Errorf("response %d is %d bytes, want <= 1025", i, len(responses[i]))
		}
	}
}

func TestWorker_DoesNotSwallowSystemExit(t *testing.T) {
	out, _ := runWorker(t, "OK", "EXIT", "OK")
	if got := strings.Count(out, linter.PKIMETAL_ENDOFRESULTS); got != 1 {
		t.Errorf("got %d responses, want 1 (the worker should exit on SystemExit); output = %q", got, out)
	}
}
