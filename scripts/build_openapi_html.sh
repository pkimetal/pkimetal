#!/bin/bash
# Run from the repo root so npm uses the checked-in package-lock.json.
cd "$(dirname "$(readlink -f "$0")")/.."
npm ci
./node_modules/.bin/redocly build-docs doc/openapi.yaml -o doc/openapi.html
