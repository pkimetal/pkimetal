package ftfy

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/utils"

	"github.com/sergi/go-diff/diffmatchpatch"
)

type Ftfy struct{}

var GitDescribeTagsAlways, PythonDir string
var dmp *diffmatchpatch.DiffMatchPatch = diffmatchpatch.New()

func init() {
	// Get ftfy package details, either embedded during the build process or from pipx; if requested in the config, autodetect the site-packages directory.
	var ftfyVersion string
	if GitDescribeTagsAlways != "" {
		ftfyVersion, config.Config.Linter.Ftfy.PythonDir = GitDescribeTagsAlways, PythonDir
	} else {
		ftfyVersion, config.Config.Linter.Ftfy.PythonDir = linter.GetPackageDetailsFromPipx("ftfy", config.Config.Linter.Ftfy.PythonDir)
	}
	switch config.Config.Linter.Ftfy.PythonDir {
	case "", "autodetect":
		panic("ftfy: PythonDir must be set")
	}

	// Register ftfy.
	(&linter.Linter{
		Name:         "ftfy",
		Version:      ftfyVersion,
		Url:          "https://github.com/rspeer/python-ftfy",
		Unsupported:  linter.NonCertificateProfileIDs,
		NumInstances: config.Config.Linter.Ftfy.NumProcesses,
		Interface:    func() linter.LinterInterface { return &Ftfy{} },
	}).Register()
}

func (l *Ftfy) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	// Start ftfy server and configure STDIN/STDOUT pipes.
	// ftfy is run in a separate process, so the instances are "external"; however, since the input is preprocessed in the frontend we return external=false.
	// Configure ftfy "normalization" and other features to reduce the likelihood of false positives.
	return true, config.Config.Linter.Ftfy.PythonDir, "python3",
		[]string{"-c", `#!/usr/bin/python3
from ftfy import fix_text, TextFixerConfig
from sys import stdin

config = TextFixerConfig(unescape_html=True, fix_latin_ligatures=False, fix_character_width=False, uncurl_quotes=False, normalization=None, explain=False)

def run_ftfy(line):
	try:
		return fix_text(line, config=config)
	except Exception as e:
		return "F: Exception: " + str(e)

try:
	for line in stdin:
		print(run_ftfy(line), end='', flush=True)
except KeyboardInterrupt:
	pass
`}
}

func (l *Ftfy) StopInstance(lin *linter.LinterInstance) {
}

func removePrintableASCIIExceptSemicolon(r rune) rune {
	if r < ' ' || r > '~' || r == ';' {
		return r
	} else {
		return -1
	}
}

func (l *Ftfy) HandleRequest(lin *linter.LinterInstance, lreq *linter.LintingRequest, ctx context.Context) []linter.LintingResult {
	var lres []linter.LintingResult

	// Produce a one-line string that concatenates everything that we want ftfy to check.  (Subject.String() does some conversion and so is unsuitable for this purpose).
	var ftfyInput string
	for _, atv := range lreq.Cert.Subject.Names {
		switch atv.Value.(type) {
		case string:
			ftfyInput += " " + atv.Value.(string)
		}
	}

	if ftfyInput = strings.ReplaceAll(ftfyInput, "\n", " "); strings.Map(removePrintableASCIIExceptSemicolon, ftfyInput) == "" {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_INFO,
			Finding:  "ftfy not invoked, because Subject DN only contains printable ASCII characters",
		})
	} else { // At least one character is not printable ASCII.
		// ftfy can't deal with the Unicode Replacement Character (\uFFFD), but since this character always indicates that the string is incorrect we should always block it.
		if strings.ContainsRune(ftfyInput, '\uFFFD') {
			lres = append(lres, linter.LintingResult{
				Severity: linter.SEVERITY_ERROR,
				Finding:  "Unicode replacement character(s) present",
			})
		}
		if _, err := io.WriteString(lin.Stdin, ftfyInput+"\n"); err != nil {
			lres = append(lres, linter.LintingResult{
				Severity: linter.SEVERITY_FATAL,
				Finding:  fmt.Sprintf("Could not write to stdin: %v", err),
			})
		} else if !lin.Stdout.Scan() {
			lres = append(lres, linter.LintingResult{
				Severity: linter.SEVERITY_FATAL,
				Finding:  "Stdout.Scan() => false",
			})
		} else if ftfyOutput := lin.Stdout.Text(); ftfyInput != ftfyOutput {
			// ftfy "fixed" one or more things that we haven't listed as false positives.
			// Return finding(s).
			field := ""
			for _, diff := range dmp.DiffMain(ftfyInput, ftfyOutput, false) {
				switch diff.Type {
				case diffmatchpatch.DiffDelete:
					field = diff.Text
				case diffmatchpatch.DiffInsert:
					lres = append(lres, linter.LintingResult{
						Severity: linter.SEVERITY_WARNING,
						Field:    fmt.Sprintf("'%s' (0x%s)", field, hex.EncodeToString(utils.S2B(field))),
						Finding:  fmt.Sprintf("Should be '%s' (0x%s)", diff.Text, hex.EncodeToString(utils.S2B(diff.Text))),
					})
					field = ""
				}
			}
		}
	}

	return lres
}
