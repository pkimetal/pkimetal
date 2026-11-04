# HTTP linters

HTTP linters let you add your own linters to pkimetal without rebuilding it. An HTTP linter is an external endpoint that pkimetal sends each certificate, CRL, or OCSP response to, in the format described below. pkimetal reports the endpoint's findings alongside those of its other linters.

## Configuration

HTTP linters are declared in `config.yaml` (e.g. `/config/config.yaml`) under `linter.httpLinters`. Several endpoints can be declared; each one is a separate linter, with its own name in the results and in the `/linters` list. HTTP linters cannot be declared with environment variables.

```yaml
linter:
  httpLinters:
    - name: mylinter                  # Required. The linter name shown in results; must be unique.
      url: http://mylinter:8000/lint  # Required. An http or https URL.
      numGoroutines: 1                # Optional, default 1. The number of concurrent requests; 0 disables the linter.
      timeout: 5s                     # Optional, default 5s (or half of linter.backendTimeout, if less). Must be less than linter.backendTimeout (default 30s).
      artifacts: [certificate]        # Optional, default [certificate]. Any of: certificate, crl, ocsp.
      errorSeverity: bug              # Optional, default bug. The severity reported when a request fails.
      timeoutSeverity: notice         # Optional, default notice. The severity reported when a request times out.
      version: 1.0.0                  # Optional. Shown in the /linters list.
      headers:                        # Optional. Extra HTTP headers sent with each request.
        Authorization: Bearer abc123
      tls:                            # Optional. Only for https URLs.
        caFile: /config/ca.pem        # Trust only the CA certificate(s) in this file, instead of the system roots.
        certFile: /config/client.pem  # A client certificate for mutual TLS. Requires keyFile.
        keyFile: /config/client.key   # The client certificate's private key. Requires certFile.
```

pkimetal refuses to start if an HTTP linter has no `name` or `url`, if `url` is not an absolute `http` or `https` URL, if `url` contains credentials (e.g. `https://user:password@host/`; use `headers` instead), if a name is `pkimetal` (which is reserved) or is already used by another HTTP linter or a built-in linter, if `artifacts` or a severity is not one of the listed values, if `numGoroutines` or `timeout` is negative, if `timeout` is not less than `linter.backendTimeout`, if a header name or value is invalid (e.g. a value containing a line break) or the header is `Host` (which is taken from `url`), if `tls` is set for an `http` URL, if only one of `certFile` and `keyFile` is set, or if a TLS file cannot be loaded.

An endpoint is only sent the artifact types listed in `artifacts`.

The `url`, without its query string, is shown by the `/linters` endpoint and on pkimetal's web page; findings that report a failed request do not include it. Put API keys in `headers` rather than in the URL.

Header names are case-insensitive. The configuration loader lowercases them (e.g. `authorization`), which does not affect how they are sent.

## Request

For each artifact, pkimetal sends a `POST` request to the configured `url`, with `Content-Type: application/json` and `User-Agent: pkimetal`, plus any configured headers:

```json
{"b64input": "MIIF...", "profile": "tbr_leaf_tlsserver_ov", "artifact": "certificate"}
```

- `b64input`: the Base64-encoded DER of the artifact. Pre-issuance input (e.g. `/linttbscert`) is sent as a signed artifact with a dummy signature.
- `profile`: the name of the profile, as listed by the `/profiles` endpoint. `autodetect` is always resolved to a specific profile first.
- `artifact`: `certificate`, `crl`, or `ocsp`.

`b64input` and `profile` have the same names and meanings as the parameters of pkimetal's own lint endpoints.

## Response

The endpoint responds with HTTP status 200 and a JSON array of findings, in the same format as pkimetal's own responses:

```json
[{"Finding": "Subject CN contains 'example'", "Severity": "warning", "Field": "tbsCertificate.subject.commonName", "Code": "subjectcn_example"}]
```

- `Finding` and `Severity` are required. `Field` and `Code` are optional. A `Linter` value may be included, but is replaced with the configured `name`.
- `Severity` must be one of `debug`, `info`, `notice`, `warning`, `error`, `bug`, or `fatal`. (`meta` is reserved for pkimetal.)
- An empty array (`[]`) means that there are no findings.

[`doc/http-linter-openapi.yaml`](../http-linter-openapi.yaml) describes this request and response as an OpenAPI document.

## Failures

If a request does not succeed, pkimetal reports a single finding from that linter instead of the endpoint's findings:

- If the request takes longer than `timeout`: `API request timed out`, with severity `timeoutSeverity`.
- If the connection or TLS handshake fails: the error, with severity `errorSeverity`.
- If the HTTP status is not 200: `API request failed: HTTP <status>`, with severity `errorSeverity`. Redirects are not followed, so configured headers are never sent to another URL.
- If the response is larger than 16 MiB, is not a JSON array, or contains a finding with no `Finding` or with an invalid `Severity`: `invalid API response: <reason>`, with severity `errorSeverity`. The whole response is rejected.

## Example

[`examples/httplinter/subjectcn`](../../examples/httplinter/subjectcn/main.go) is a complete example endpoint in Go. It warns when a certificate's Subject CN contains "example".

```bash
go run ./examples/httplinter/subjectcn -listen :8000 &
mkdir -p config
cat > config/config.yaml <<'EOF'
linter:
  httpLinters:
    - name: subjectcn
      url: http://host.docker.internal:8000/
EOF
docker run -p 8080:8080 --add-host=host.docker.internal:host-gateway \
  --mount type=bind,src="$PWD/config",dst=/config,readonly \
  ghcr.io/pkimetal/pkimetal
```
