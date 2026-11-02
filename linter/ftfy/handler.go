package ftfy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/utils"

	"github.com/sergi/go-diff/diffmatchpatch"
)

type Ftfy struct {
	requestID atomic.Uint64
}

var Version, PythonDir string
var dmp *diffmatchpatch.DiffMatchPatch = diffmatchpatch.New()

func init() {
	if config.Config.Linter.Ftfy.NumProcesses > 0 {
		// Get ftfy package details, either embedded during the build process or from pipx; if requested in the config, autodetect the site-packages directory.
		if Version != "" {
			config.Config.Linter.Ftfy.PythonDir = PythonDir
		} else {
			Version, config.Config.Linter.Ftfy.PythonDir = linter.GetPackageDetailsFromPipx("ftfy", config.Config.Linter.Ftfy.PythonDir)
		}

		switch config.Config.Linter.Ftfy.PythonDir {
		case "", "autodetect":
			panic("ftfy: PythonDir must be set")
		}
	}

	// Register ftfy.
	(&linter.Linter{
		Name:         "ftfy",
		Version:      Version,
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
import base64
import sys
from ftfy import fix_text, TextFixerConfig

config = TextFixerConfig(unescape_html=True, fix_latin_ligatures=False, fix_character_width=False, uncurl_quotes=False, normalization=None, explain=False)

try:
	for line in sys.stdin.buffer:
		request_id = line.partition(b"\t")[0]
		try:
			request_id, encoded_input = line.rstrip(b"\n").split(b"\t", 1)
			text = base64.b64decode(encoded_input, validate=True).decode("utf-8", "surrogateescape")
			output = fix_text(text, config=config)
			encoded_output = base64.b64encode(output.encode("utf-8", "surrogateescape"))
		except Exception as e:
			encoded_output = base64.b64encode(("F: Exception: " + str(e)).encode("utf-8", "surrogateescape"))
		sys.stdout.buffer.write(request_id + b"\t" + encoded_output + b"\n")
		sys.stdout.buffer.flush()
except KeyboardInterrupt:
	pass
except Exception as e:
	print("ftfy worker failed: " + str(e), file=sys.stderr, flush=True)
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

func isFtfyLineSeparator(r rune) bool {
	switch r {
	case '\n', '\r', '\u0085', '\u2028', '\u2029':
		return true
	default:
		return false
	}
}

func ftfyInputIssues(input string) (invalidUTF8, replacementCharacter bool, lineSeparators []string) {
	seen := make(map[rune]struct{})
	for i := 0; i < len(input); {
		r, size := utf8.DecodeRuneInString(input[i:])
		i += size
		if r == utf8.RuneError {
			if size == 1 {
				invalidUTF8 = true
			} else {
				replacementCharacter = true
			}
		}
		if isFtfyLineSeparator(r) {
			if _, ok := seen[r]; !ok {
				lineSeparators = append(lineSeparators, fmt.Sprintf("U+%04X", r))
				seen[r] = struct{}{}
			}
		}
	}
	return invalidUTF8, replacementCharacter, lineSeparators
}

func replaceFtfyLineSeparator(r rune) rune {
	if isFtfyLineSeparator(r) {
		return ' '
	}
	return r
}

func sanitizeFtfyInput(input string) string {
	input = strings.ToValidUTF8(input, "\uFFFD")
	return strings.Map(replaceFtfyLineSeparator, input)
}

func parseFtfyResponse(line, requestID string) (string, error) {
	response := strings.SplitN(line, "\t", 2)
	if len(response) != 2 || response[0] != requestID {
		return "", fmt.Errorf("unexpected worker response; expected request %s, got %q", requestID, line)
	}
	decodedOutput, err := base64.StdEncoding.DecodeString(response[1])
	if err != nil {
		return "", fmt.Errorf("invalid worker response encoding: %w", err)
	}
	if !utf8.Valid(decodedOutput) {
		return "", fmt.Errorf("worker response is not valid UTF-8")
	}
	return string(decodedOutput), nil
}

func (l *Ftfy) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	lres, err := l.HandleRequestWithError(ctx, lin, lreq)
	if err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("ftfy: %v", err),
		})
	}
	return lres
}

func (l *Ftfy) HandleRequestWithError(_ context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) ([]linter.LintingResult, error) {
	var lres []linter.LintingResult

	// Produce a one-line string that concatenates everything that we want ftfy to check.  (Subject.String() does some conversion and so is unsuitable for this purpose).
	var ftfyInput string
	for _, atv := range lreq.Cert.Subject.Names {
		switch atv.Value.(type) {
		case string:
			ftfyInput += " " + atv.Value.(string)
		}
	}

	invalidUTF8, replacementCharacter, lineSeparators := ftfyInputIssues(ftfyInput)
	if invalidUTF8 {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_ERROR,
			Finding:  "Invalid UTF-8 byte sequence(s) present",
		})
	}
	if replacementCharacter {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_ERROR,
			Finding:  "Unicode replacement character(s) present",
		})
	}
	if len(lineSeparators) > 0 {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_ERROR,
			Finding:  "Subject DN contains line separator character(s): " + strings.Join(lineSeparators, ", "),
		})
	}

	invokeFtfy := (strings.Map(removePrintableASCIIExceptSemicolon, ftfyInput) != "")
	ftfyInput = sanitizeFtfyInput(ftfyInput)
	if !invokeFtfy {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_INFO,
			Finding:  "ftfy not invoked, because Subject DN only contains printable ASCII characters",
		})
		return lres, nil
	}

	requestID := strconv.FormatUint(l.requestID.Add(1), 10)
	encodedInput := base64.StdEncoding.EncodeToString([]byte(ftfyInput))
	request := requestID + "\t" + encodedInput + "\n"
	if n, err := io.WriteString(lin.Stdin, request); err != nil {
		return lres, fmt.Errorf("could not write to stdin: %w", err)
	} else if n != len(request) {
		return lres, io.ErrShortWrite
	}
	if !lin.Stdout.Scan() {
		if err := lin.Stdout.Err(); err != nil {
			return lres, fmt.Errorf("stdout scan failed: %w", err)
		}
		return lres, io.ErrUnexpectedEOF
	}
	if lin.Stdout.Oversized() {
		return lres, linter.ErrResponseTooLong
	}
	ftfyOutput, err := parseFtfyResponse(lin.Stdout.Text(), requestID)
	if err != nil {
		return lres, err
	}
	if ftfyInput != ftfyOutput {
		// ftfy "fixed" one or more things that we haven't listed as false positives.
		// Return finding(s).
		var deleted string
		var changes [][2]string
		for _, diff := range dmp.DiffMain(ftfyInput, ftfyOutput, false) {
			switch diff.Type {
			case diffmatchpatch.DiffDelete:
				deleted = diff.Text
				changes = append(changes, [2]string{deleted, ""})
			case diffmatchpatch.DiffInsert:
				if deleted != "" {
					changes[len(changes)-1][1] = diff.Text
					deleted = ""
				} else {
					changes = append(changes, [2]string{"", diff.Text})
				}
			case diffmatchpatch.DiffEqual:
				deleted = ""
			}
		}
		for _, change := range changes {
			var field, finding string
			if change[0] == "" {
				field = "Absent"
			} else {
				field = fmt.Sprintf("'%s' (0x%s)", change[0], hex.EncodeToString(utils.S2B(change[0])))
			}
			if change[1] == "" {
				finding = "Should be absent"
			} else {
				finding = fmt.Sprintf("Should be '%s' (0x%s)", change[1], hex.EncodeToString(utils.S2B(change[1])))
			}
			lres = append(lres, linter.LintingResult{
				Severity: linter.SEVERITY_WARNING,
				Field:    field,
				Finding:  finding,
			})
		}
	}

	return lres, nil
}

func (l *Ftfy) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
