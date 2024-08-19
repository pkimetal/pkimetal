package request

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func copyright() string {
	var s strings.Builder

	copyrightFromYear := 2024
	s.WriteString(fmt.Sprintf(`<P class="copyright">&copy; Sectigo Limited %d`, copyrightFromYear))
	copyrightToYear := time.Now().Year()
	if copyrightToYear > copyrightFromYear {
		s.WriteString(fmt.Sprintf(`-%d`, copyrightToYear))
	}
	s.WriteString(`. All rights reserved.</P>`)

	return s.String()
}

func CSS(fhctx *fasthttp.RequestCtx) {
	var response strings.Builder
	response.WriteString(`
div {
  font: 8pt Roboto, sans-serif;
  font-style: italic
}
table {
  border-collapse: collapse;
  color: #222222;
  font: 12pt Roboto, sans-serif;
  margin-left: auto;
  margin-right: auto
}
td {
  padding: 5px 10px 0px 0px;
  vertical-align: top
}
select {
  font: 10pt Roboto, sans-serif
}
textarea {
  font: 8pt Roboto Mono, monospace
}
.title {
  background: transparent;
  background: linear-gradient(top,rgba(38,38,38,0.8),#e6e6e6 25%,#ffffff 38%,#c5c5c5 63%,#f7f7f7 87%,rgba(38,38,38,0.8));
  background: -webkit-linear-gradient(top, rgba(38,38,38,0.5),#e6e6e6 25%,#ffffff 38%,rgba(0,0,0,0.25) 63%,#e6e6e6 87%,rgba(38,38,38,0.4));
  box-shadow: inset 0px 1px 0px rgba(255,255,255,1),0px 1px 3px rgba(0,0,0,0.3);
  color: #888888;
  display: inline-block;
  font: 18pt Roboto, sans-serif;
  padding: 5px 30px;
  text-align: center;
  text-shadow: 0px -1px 0px rgba(0,0,0,0.4);
  vertical-align: middle
}
.button {
  background: transparent;
  background: linear-gradient(top, rgba(38, 38, 38, 0.8), #e6e6e6 25%, #ffffff 38%, #c5c5c5 63%, #f7f7f7 87%, rgba(38, 38, 38, 0.8));
  background: -webkit-linear-gradient(top, rgba(38, 38, 38, 0.5), #e6e6e6 25%, #ffffff 38%, rgba(0, 0, 0, 0.25)  63%, #e6e6e6 87%, rgba(38, 38, 38, 0.4));
  border: 1px solid #ba6;
  border-color: #7c7c7c;
  border-radius: 5px;
  box-shadow: inset 0px 1px 0px rgba(255,255,255,1),0px 1px 3px rgba(0,0,0,0.3);
  color: #44BB88;
  cursor: pointer;
  display: inline-block;
  font: 14pt Roboto, sans-serif;
  font-weight: bold;
  height: 40px;
  padding: 5px 25px;
  text-shadow: 0px -1px 0px rgba(0,0,0,0.4)
}
.button:active{
  -webkit-transform: translateY(2px);
  transform: translateY(2px)
}
.copyright {
  font: 8pt Roboto, sans-serif;
  color: #00B373;
  text-align: center
}`)

	logger.SetDetails(fhctx, zap.InfoLevel, "CSS", nil, nil)
	fhctx.SetBodyString(response.String())
	fhctx.SetContentType("text/css")
	fhctx.SetStatusCode(fasthttp.StatusOK)
}

func FrontPage(fhctx *fasthttp.RequestCtx) {
	var response strings.Builder
	response.WriteString(`<!DOCTYPE HTML>
<HTML>
<HEAD>
  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <TITLE>pkimetal | PKI Meta-Linter</TITLE>
  <LINK href="//fonts.googleapis.com/css?family=Roboto+Mono|Roboto:400,400i,700,700i" rel="stylesheet">
  <LINK href="/` + ENDPOINTSTRING_CSS + `" rel="stylesheet">
</HEAD>
<BODY>
  <TABLE>
    <TR>
      <TD style="text-align:center;vertical-align:middle"><A href="//` + linter.GetPackagePath() + `/releases" target="_blank"><DIV class="title">` + linter.PKIMETAL_NAME + ` ` + linter.VersionString(config.PkimetalVersion) + `</DIV></A></TD>
      <TD style="padding-left:50px"><A href="//` + linter.GetPackagePath() + `" target="_blank"><IMG src="/mascot.jpg" width="100" height="100"></A></TD>
    </TR>
    <TR>
      <TD>
        <BR><A href="//` + linter.GetPackagePath() + `/blob/main/doc/REST_API.md" target="_blank">REST API Documentation [GitHub]</A>
        <BR><BR><BR>Example webpages that use the linting REST APIs:
        <UL>
          <LI><A href="/` + ENDPOINTSTRING_LINTCERT + `">` + ENDPOINTSTRING_LINTCERT + `</A> - Lint a Certificate</LI>
          <LI><A href="/` + ENDPOINTSTRING_LINTTBSCERT + `">` + ENDPOINTSTRING_LINTTBSCERT + `</A> - Lint a to-be-signed Certificate</LI>
          <LI><A href="/` + ENDPOINTSTRING_LINTCRL + `">` + ENDPOINTSTRING_LINTCRL + `</A> - Lint a CRL</LI>
          <LI><A href="/` + ENDPOINTSTRING_LINTTBSCRL + `">` + ENDPOINTSTRING_LINTTBSCRL + `</A> - Lint a to-be-signed CRL</LI>
          <LI><A href="/` + ENDPOINTSTRING_LINTOCSP + `">` + ENDPOINTSTRING_LINTOCSP + `</A> - Lint an OCSP Response</LI>
          <LI><A href="/` + ENDPOINTSTRING_LINTTBSOCSP + `">` + ENDPOINTSTRING_LINTTBSOCSP + `</A> - Lint a to-be-signed OCSP Response</LI>
        </UL>
        <BR>Other APIs:
        <UL>
          <LI><A href="/` + ENDPOINTSTRING_LINTERS + `">` + ENDPOINTSTRING_LINTERS + `</A> - List all available linters</LI>
          <LI><A href="/` + ENDPOINTSTRING_PROFILES + `">` + ENDPOINTSTRING_PROFILES + `</A> - List all available profiles</LI>
        </UL>
      </TD>
      <TD style="vertical-align:bottom;padding-left:50px">` + availableLinters() + builtAt() + `<BR></TD>
    </TR>
  </TABLE>
  <BR><BR><BR>` + copyright() + `
</BODY>
</HTML>
`)

	logger.SetDetails(fhctx, zap.InfoLevel, "Front page", nil, nil)
	fhctx.SetBodyString(response.String())
	fhctx.SetContentType("text/html")
	fhctx.SetStatusCode(fasthttp.StatusOK)
}

func APIWebpage(fhctx *fasthttp.RequestCtx, endpoint string) {
	var response strings.Builder
	response.WriteString(`<!DOCTYPE HTML>
<HTML>
<HEAD>
  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <TITLE>pkimetal | PKI Meta-Linter</TITLE>
  <LINK href="//fonts.googleapis.com/css?family=Roboto+Mono|Roboto:400,400i,700,700i" rel="stylesheet">
  <LINK href="/` + ENDPOINTSTRING_CSS + `" rel="stylesheet">
</HEAD>
<BODY>
  <FORM method="post">
    <TABLE>
      <TR>
        <TD style="text-align:center;vertical-align:middle"><A href="//` + linter.GetPackagePath() + `/releases" target="_blank"><DIV class="title">` + linter.PKIMETAL_NAME + ` ` + linter.VersionString(config.PkimetalVersion) + `</DIV></A></TD>
        <TD><A href="//` + linter.GetPackagePath() + `" target="_blank"><IMG src="/mascot.jpg" width="100" height="100"></A></TD>
      </TR>
      <TR>
        <TD>`)
	inputType := ""
	switch endpoint {
	case ENDPOINTSTRING_LINTCERT:
		inputType = `Certificate/Precertificate`
	case ENDPOINTSTRING_LINTTBSCERT:
		inputType = `To-be-signed Certificate/Precertificate`
	case ENDPOINTSTRING_LINTCRL:
		inputType = `Certificate Revocation List`
	case ENDPOINTSTRING_LINTTBSCRL:
		inputType = `To-be-signed Certificate Revocation List`
	case ENDPOINTSTRING_LINTOCSP:
		inputType = `OCSP Response`
	case ENDPOINTSTRING_LINTTBSOCSP:
		inputType = `To-be-signed OCSP Response`
	}
	response.WriteString(inputType + ` (PEM/Base64):
          <BR><TEXTAREA name="b64input" cols="70" rows="18" autofocus autoCorrect="off" autoCapitalize="off" spellCheck="false"></TEXTAREA>
        </TD>
        <TD>Response Format:
          <BR><SELECT name="format" size="3" style="overflow:hidden">
            <OPTION value="html" selected>html</OPTION>
            <OPTION value="json">json</OPTION>
            <OPTION value="text">text</OPTION>
          </SELECT>
          <BR><BR>Minimum Severity:
          <BR><SELECT name="severity" size="8" style="overflow:hidden">
            <OPTION value="meta" selected>meta</OPTION>
            <OPTION value="debug">debug</OPTION>
            <OPTION value="info">info</OPTION>
            <OPTION value="notice">notice</OPTION>
            <OPTION value="warning">warning</OPTION>
            <OPTION value="error">error</OPTION>
            <OPTION value="bug">bug</OPTION>
            <OPTION value="fatal">fatal</OPTION>
          </SELECT>
        </TD>
      </TR>
      <TR>
        <TD>Profile:
          <BR><SELECT name="profile" size="13">`)
	for id, profile := range linter.AllProfilesOrdered {
		isShown := false
		switch endpoint {
		case ENDPOINTSTRING_LINTCERT, ENDPOINTSTRING_LINTTBSCERT:
			if !slices.Contains(linter.NonCertificateProfileIDs, linter.ProfileId(id)) {
				isShown = true
			}
		case ENDPOINTSTRING_LINTCRL, ENDPOINTSTRING_LINTTBSCRL:
			if linter.ProfileId(id) == linter.AUTODETECT || slices.Contains(linter.CrlProfileIDs, linter.ProfileId(id)) {
				isShown = true
			}
		case ENDPOINTSTRING_LINTOCSP, ENDPOINTSTRING_LINTTBSOCSP:
			if linter.ProfileId(id) == linter.AUTODETECT || slices.Contains(linter.OcspProfileIDs, linter.ProfileId(id)) {
				isShown = true
			}
		}
		if isShown {
			response.WriteString(`
            <OPTION value="` + profile.Name + `"`)
			if linter.ProfileId(id) == linter.AUTODETECT {
				response.WriteString(` selected`)
			}
			response.WriteString(`>`)
			if profile.Source != "" {
				response.WriteString(`[` + profile.Source + `] `)
			}
			response.WriteString(profile.Description + `</OPTION>`)
		}
	}
	response.WriteString(`
          </SELECT>
        </TD>
        <TD>
          <INPUT class="button" type="submit" value="` + endpoint + `">
          <BR><BR><BR>` + availableLinters() + builtAt() + `
        </TD>
      </TR>
    </TABLE>
  </FORM>
  <BR><BR><BR>` + copyright() + `
</BODY>
</HTML>
`)

	logger.SetDetails(fhctx, zap.InfoLevel, endpoint+" webpage", nil, nil)
	fhctx.SetBodyString(response.String())
	fhctx.SetContentType("text/html")
	fhctx.SetStatusCode(fasthttp.StatusOK)
}

func availableLinters() string {
	var al strings.Builder
	al.WriteString(`Available Linters:<DIV style="font-size:10pt;font-style:normal">`)
	for _, l := range linter.Linters {
		if l.NumInstances <= 0 {
			al.WriteString(`<S style="color:#888888">`)
		}
		al.WriteString(`<A href="` + l.Url + `">` + l.Name + `</A> ` + linter.VersionString(l.Version))
		if l.NumInstances <= 0 {
			al.WriteString(`</S>`)
		}
		al.WriteString(`<BR>`)
	}
	al.WriteString(`</DIV>`)
	return al.String()
}

func builtAt() string {
	return `<BR>Built at:<DIV style="font-size:8pt;font-style:normal">` + config.BuildTimestamp + `</DIV>`
}
