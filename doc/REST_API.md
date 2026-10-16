# pkimetal: REST API Documentation

## OpenAPI

An [OpenAPI](https://swagger.io/specification/) definition for pkimetal is provided by [openapi.yaml](/doc/openapi.yaml) and rendered in HTML [here](https://pkimetal.github.io/pkimetal/openapi.html).

## POST parameters

The HTTP POST API endpoints all accept the following common parameters:

Name | Required? | Default Value | Description
--- | --- | --- | ---
b64input | Required | n/a | The Base64 or PEM-encoded input.
format | Optional | json, or as configured | The desired response format.
profile | Optional | autodetect | The name of the profile that the input is intended to match.
severity | Optional | meta | The minimum severity level of linter findings that should be included in the response.

Each API also supports a purpose-specific alternative name for `b64input`.

The response `format` must be one of the following options:

- html
- json
- text

Use the [profiles](#get-endpoints) GET endpoint to list the supported values for `profile`. The profile must be for the type of input that the endpoint accepts (e.g., a CRL profile for `/lintcrl` and `/linttbscrl`); otherwise, the response contains a single fatal finding: "Profile not applicable to this endpoint".

The minimum `severity` must be one of the following options:

- meta
- debug
- info
- notice
- warning
- error
- bug
- fatal

The "meta" severity level includes informational "findings" added by pkimetal itself. The other severity levels are used for the findings of the various linters.

If the request is invalid (e.g., empty body, or unrecognised input, profile, or severity), the HTTP status is 200 and the response contains a single fatal finding from pkimetal that describes the problem. The exception is an unrecognised `format`, for which the HTTP status is 400 and the response body is empty.

If the request is not completed within the server's request timeout (`server.requestTimeout`, default 30s), the HTTP status is 503.

## POST endpoints

Endpoint | Description | Alternative name for b64input
--- | --- | ---
/lintcert | Lint a signed Certificate or Precertificate | b64cert
/linttbscert | Lint a to-be-signed Certificate or Precertificate | b64tbscert
/lintcrl | Lint a signed CRL | b64crl
/linttbscrl | Lint a to-be-signed CRL | b64tbscrl
/lintocsp | Lint a signed OCSP Response | b64ocsp
/linttbsocsp | Lint a to-be-signed OCSP Response | b64tbsocsp

## GET endpoints

Endpoint | Description
--- | ---
/linters | Return a JSON array that lists information about the available linters.
/profiles | Return a JSON array that lists information about the available input profiles.

### Web forms

Browse (i.e., send a GET request) to any of the POST endpoints.
