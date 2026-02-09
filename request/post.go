package request

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/health"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"
	"github.com/pkimetal/pkimetal/utils"

	json "github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
	"github.com/zmap/zcrypto/x509"

	"go.uber.org/zap"
)

type RequestInfo struct {
	endpoint        Endpoint
	profileId       linter.ProfileId
	minimumSeverity linter.SeverityLevel
	// Input(s), in various original/processed forms.
	b64Input     []byte // PEM or base64-encoded string.
	decodedInput []byte
	cert         *x509.Certificate
}

type LintResult struct {
	Linter   string
	Finding  string
	Field    string `json:"Field,omitempty"`
	Code     string `json:"Code,omitempty"`
	Severity string
}

func getResponseFormat(fhctx *fasthttp.RequestCtx) config.ResponseFormat {
	if f := paramS(fhctx, "format"); f != "" {
		return config.ParseResponseFormat(f)
	} else {
		switch utils.B2S(fhctx.Request.Header.Peek("Accept")) {
		case "text/html":
			return config.RESPONSEFORMAT_HTML
		case "application/json":
			return config.RESPONSEFORMAT_JSON
		case "text/plain":
			return config.RESPONSEFORMAT_TEXT
		}
	}

	return config.DefaultResponseFormat
}

func POST(fhctx *fasthttp.RequestCtx, path string) int {
	status := fasthttp.StatusBadRequest

	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), fhctx.Time().Add(time.Duration(config.Config.Server.RequestTimeout)))
	defer cancel()

	doneChan := make(chan int, 1)
	go func() {
		var ri RequestInfo
		var err error
		var ok bool
		var responseFormat config.ResponseFormat
		var errorMessage string
		var lrespFiltered []LintResult
		if !ri.GetPOSTEndpoint(path) {
			status = fasthttp.StatusNotFound
			logger.SetDetails(fhctx, zap.InfoLevel, "Invalid endpoint", nil, nil)
		} else if responseFormat = getResponseFormat(fhctx); responseFormat == -1 {
			errorMessage = "Unrecognised response format"
		} else if requestBody := fhctx.Request.Body(); len(requestBody) == 0 {
			errorMessage = "Empty request body"
		} else if err = ri.GetInput(fhctx); err != nil {
			errorMessage = "Unrecognised input"
		} else if !ri.GetProfile(paramS(fhctx, "profile")) {
			errorMessage = "Unrecognised profile"
		} else if ri.minimumSeverity, ok = linter.Severity[paramS(fhctx, "severity")]; !ok {
			errorMessage = "Unrecognised severity"
		} else {
			// Construct the linting request.
			lreq := linter.LintingRequest{
				B64Input:     utils.B2S(ri.b64Input),
				DecodedInput: ri.decodedInput,
				Cert:         ri.cert,
				ProfileId:    ri.profileId,
				QueuedAt:     time.Now(),
				RespChannel:  make(chan linter.LintingResult),
			}

			// Send the linting request to (one of) each linter's backend(s), for each linter that is both available and applicable.
			var lresp []linter.LintingResult
			nlresp := 0
			for _, l := range linter.Linters {
				if isApplicable := !slices.Contains(l.Unsupported, lreq.ProfileId); isApplicable && (l.NumInstances > 0) {
					l.ReqChannel <- lreq
					nlresp++
				} else {
					lresp = append(lresp, linter.LintingResult{
						LinterName: l.Name,
						Severity:   linter.SEVERITY_META,
						Finding:    fmt.Sprintf("%s: Not used [Available:%t, Applicable:%t]", l.Name, (l.NumInstances > 0), isApplicable),
					})
				}
			}

			// Wait for all of the used linters to finish writing results to the response channel.
			for nlresp > 0 {
				resp := <-lreq.RespChannel
				if resp.LinterName == linter.PKIMETAL_NAME && resp.Finding == linter.PKIMETAL_ENDOFRESULTS {
					nlresp--
				} else {
					lresp = append(lresp, resp)
				}
			}

			// Sort the results by Linter Name, then Severity (most severe first), then Finding description.
			sort.Slice(lresp, func(i, j int) bool {
				if lresp[i].LinterName != lresp[j].LinterName {
					return lresp[i].LinterName < lresp[j].LinterName
				} else if lresp[i].Severity != lresp[j].Severity {
					return lresp[i].Severity > lresp[j].Severity
				} else {
					return lresp[i].Finding < lresp[j].Finding
				}
			})

			// Prepend a meta result with the selected profile and the pkimetal version.
			lresp = append([]linter.LintingResult{{
				LinterName: linter.PKIMETAL_NAME,
				Severity:   linter.SEVERITY_META,
				Finding:    fmt.Sprintf("Profile: %s; Version: %s", linter.AllProfiles[lreq.ProfileId].Name, linter.VersionString(config.PkimetalVersion)),
			}}, lresp...)

			// Filter out results that are below the requested minimum severity level.
			for _, lres := range lresp {
				if lres.Severity >= ri.minimumSeverity {
					lrespFiltered = append(lrespFiltered, LintResult{
						Linter:   lres.LinterName,
						Finding:  lres.Finding,
						Field:    lres.Field,
						Code:     lres.Code,
						Severity: linter.SeverityString[lres.Severity],
					})
				}
			}
		}

		if errorMessage == "" {
			logger.SetDetails(fhctx, zap.InfoLevel, "Linting Request", nil, []zap.Field{
				zap.Int("num_results", len(lrespFiltered)),
			})
		} else {
			logger.SetDetails(fhctx, zap.InfoLevel, "Linting Request with Error", fmt.Errorf("%s", errorMessage), []zap.Field{
				zap.Error(err),
			})
			lrespFiltered = append(lrespFiltered, LintResult{
				Linter:   linter.PKIMETAL_NAME,
				Finding:  errorMessage,
				Severity: linter.SeverityString[linter.SEVERITY_FATAL],
			})
		}

		// Add Cross-Origin Resource Sharing (CORS) response header.
		fhctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

		// Send response.
		switch responseFormat {
		case config.RESPONSEFORMAT_HTML:
			status = sendHTMLResponse(fhctx, lrespFiltered)
		case config.RESPONSEFORMAT_JSON:
			status = sendJSONResponse(fhctx, lrespFiltered)
		case config.RESPONSEFORMAT_TEXT:
			status = sendTEXTResponse(fhctx, lrespFiltered)
		}
		fhctx.SetStatusCode(status)
		doneChan <- 0
	}()

	return health.CompleteRequest(ctxWithDeadline, doneChan)
}

func paramS(fhctx *fasthttp.RequestCtx, name string) string {
	return utils.B2S(paramB(fhctx, name))
}

func paramB(fhctx *fasthttp.RequestCtx, name string) []byte {
	if arg := fhctx.PostArgs().Peek(name); len(arg) > 0 {
		return arg
	} else if arg = fhctx.QueryArgs().Peek(name); len(arg) > 0 {
		return arg
	} else if form, err := fhctx.MultipartForm(); err == nil {
		if s := form.Value[name]; len(s) > 0 {
			return utils.S2B(s[0])
		}
	}

	return nil
}

func sendHTMLResponse(fhctx *fasthttp.RequestCtx, lrespFiltered []LintResult) int {
	// Encode and send the results as an HTML webpage.
	fhctx.SetContentType("text/html; charset=UTF-8")

	var response strings.Builder
	response.WriteString(`<!DOCTYPE HTML>
	<HTML>
	<HEAD>
	  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
	  <TITLE>pkimetal | PKI Meta-Linter</TITLE>
	  <LINK href="//fonts.googleapis.com/css?family=Roboto+Mono|Roboto:400,400i,700,700i" rel="stylesheet">
	  <STYLE type="text/css">
		table {
		  border-collapse: collapse;
		  color: #222222;
		  font: 12pt Roboto, sans-serif;
		  margin: auto
		}
		td, th {
		  padding: 3px 10px
		}
	  </STYLE>
	</HEAD>
	<BODY>
	  <TABLE>
		<TR>
		  <TH>Linter</TH>
		  <TH>Severity</TH>
		  <TH>Finding</TH>
		  <TH>Field</TH>
		  <TH>Code</TH>
		</TR>`)
	if len(lrespFiltered) == 0 {
		response.WriteString(`
		<TR><TD colspan="3" align="center">No findings</TD></TR>`)
	} else {
		for _, lres := range lrespFiltered {
			style := ""
			switch lres.Severity {
			case linter.SEVERITYSTRING_META:
				style = "color:#00B373"
			case linter.SEVERITYSTRING_DEBUG:
				style = "background-color:#FAFAFA;color:#AAAAAA"
			case linter.SEVERITYSTRING_INFO:
				style = "background-color:#EFEFEF;color:#222222"
			case linter.SEVERITYSTRING_NOTICE:
				style = "background-color:#FFFFDF;color:#606000"
			case linter.SEVERITYSTRING_WARNING:
				style = "background-color:#FFEFDF;color:#DF6000"
			case linter.SEVERITYSTRING_ERROR:
				style = "background-color:#FFDFDF;color:#CC0000;font-weight:bold"
			case linter.SEVERITYSTRING_BUG, linter.SEVERITYSTRING_FATAL:
				style = "background-color:#0000AA;color:#FFFFFF;font-weight:bold"
			}
			response.WriteString(`
		<TR style="` + style + `">
		  <TD>` + lres.Linter + `</TD>
		  <TD>` + strings.ToUpper(lres.Severity) + `</TD>
		  <TD>` + lres.Finding + `</TD>
		  <TD>` + lres.Field + `</TD>
		  <TD>` + lres.Code + `</TD>
		</TR>`)
		}
	}
	response.WriteString(`
	  </TABLE>
	</BODY>
	</HTML>
	`)

	fhctx.SetBodyString(response.String())

	return fasthttp.StatusOK
}

func sendJSONResponse(fhctx *fasthttp.RequestCtx, lrespFiltered []LintResult) int {
	// Encode and send the results as JSON.
	fhctx.SetContentType("application/json; charset=UTF-8")

	if len(lrespFiltered) == 0 {
		// The JSON encoder would emit "null", but we want to return an empty array.
		fhctx.SetBodyString("[]")
	} else {
		j := json.NewEncoder(fhctx)
		j.SetEscapeHTML(false)
		if config.Config.Response.JsonPrettyPrint {
			j.SetIndent("", "  ")
		}
		if err := j.Encode(lrespFiltered); err != nil {
			logger.SetDetails(fhctx, zap.ErrorLevel, "Failed to encode JSON", nil, nil)
		}
	}

	return fasthttp.StatusOK
}

func sendTEXTResponse(fhctx *fasthttp.RequestCtx, lrespFiltered []LintResult) int {
	// Encode and send the results as tab-separated plain text.
	fhctx.SetContentType("text/plain; charset=UTF-8")

	var response strings.Builder
	for _, lres := range lrespFiltered {
		finding := lres.Finding
		if lres.Field != "" {
			finding += " [" + lres.Field + "]"
		}
		response.WriteString(fmt.Sprintf("%s\t%s\t%s\n", lres.Linter, strings.ToUpper(lres.Severity), finding))
	}

	fhctx.SetBodyString(response.String())

	return fasthttp.StatusOK
}
