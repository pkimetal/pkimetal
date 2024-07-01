# pkimetal: REST API Documentation

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

Use the [profiles](#get-endpoints) GET endpoint to list the supported values for `profile`.

The minimum `severity` must be one of the following options:

- meta
- debug
- info
- notice
- warning
- error
- bug
- fatal

The "meta" severity level includes informational "findings" added by pkimetal itself. The other security levels are used for the findings of the various linters.

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