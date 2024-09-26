package badkeys

import (
	"context"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
)

type Badkeys struct{}

var Version, PythonDir string

func init() {
	// Get badkeys package details, either embedded during the build process or from pipx; if requested in the config, autodetect the site-packages directory.
	if Version != "" {
		config.Config.Linter.Badkeys.PythonDir = PythonDir
	} else {
		Version, config.Config.Linter.Badkeys.PythonDir = linter.GetPackageDetailsFromPipx("badkeys", config.Config.Linter.Badkeys.PythonDir)
	}
	switch config.Config.Linter.Badkeys.PythonDir {
	case "", "autodetect":
		panic("badkeys: PythonDir must be set")
	}

	// Register badkeys.
	(&linter.Linter{
		Name:         "badkeys",
		Version:      Version,
		Url:          "https://github.com/badkeys/badkeys",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Badkeys.NumProcesses,
		Interface:    func() linter.LinterInterface { return &Badkeys{} },
	}).Register()
}

func (l *Badkeys) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	// Start badkeys server and configure STDIN/STDOUT pipes.
	// The printresults function is adapted from the _printresults function defined by https://github.com/badkeys/badkeys/blob/main/badkeys/runcli.py.
	return false, config.Config.Linter.Badkeys.PythonDir, "python3",
		[]string{"-c", `#!/usr/bin/python3
from sys import stdin
from badkeys.allkeys import urllookup
from badkeys.checks import allchecks, checkcrt

def printresults(key):
	if key["type"] == "unsupported":
		print(f"W: Unsupported key type")
	elif key["type"] == "unparseable":
		print(f"F: Unparseable input")
	elif key["type"] == "notfound":
		print(f"W: No key found")
	else:
		if key["results"] == {}:
			print(f"I: Key ok")
	for check, result in key["results"].items():
		sub = ""
		if "subtest" in result:
			sub = f"/{result['subtest']}"
		if sub.startswith(tuple(["/unusual_keysize", "/exponent_"])):
			print(f"I: {check}{sub}")
		else:
			print(f"E: {check}{sub} vulnerability")

profile_id = -1
pem_data = ""
try:
	for line in stdin:
		if profile_id == -1:
			profile_id = int(line.strip())
		else:
			pem_data = pem_data + line.strip() + "\n"

		if "END CERTIFICATE" in line:
			printresults(checkcrt(pem_data, checks=allchecks))
			print("` + linter.PKIMETAL_ENDOFRESULTS + `", flush=True)
			profile_id = -1
			pem_data = ""
except KeyboardInterrupt:
	pass
`}
}

func (l *Badkeys) StopInstance(lin *linter.LinterInstance) {
}

func (l *Badkeys) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	// Not used.
	return nil
}

func (l *Badkeys) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
