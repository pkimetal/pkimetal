package worker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/linter"
)

// stubBadkeys is a minimal stand-in for the badkeys package, whose checkcrt
// raises on demand.
var stubBadkeys = map[string]string{
	"badkeys/__init__.py": "",
	"badkeys/allkeys.py":  "def urllookup(*args, **kwargs):\n\treturn None\n",
	"badkeys/checks.py": `allchecks = {}

def recurse():
	return recurse()

def checkcrt(pem, checks):
	if "RECURSE" in pem:
		return recurse()
	if "VALUE" in pem:
		raise ValueError("multi\nline\tmessage")
	if "HUGE" in pem:
		raise ValueError("x" * 100000)
	return {"type": "rsa", "results": {}}
`,
}

func TestWorker_ReportsExceptionsAndKeepsServing(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	for name, content := range stubBadkeys {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	request := func(body string) string {
		return "0\n-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
	}
	cmd := exec.Command(python, "-c", Script)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(request("RECURSE") + request("VALUE") + request("HUGE") + request("OK"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("worker exited with error: %v; output = %q", err, out)
	}

	responses := strings.Split(strings.TrimSuffix(string(out), linter.PKIMETAL_ENDOFRESULTS+"\n"), linter.PKIMETAL_ENDOFRESULTS+"\n")
	if len(responses) != 4 {
		t.Fatalf("got %d responses, want 4; output = %q", len(responses), out)
	}
	for i, want := range []string{
		"F: Exception: RecursionError: ",
		"F: Exception: ValueError: multi line message\n",
		"F: Exception: ValueError: xxx",
		"I: Key ok\n",
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
