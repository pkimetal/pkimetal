#!/bin/bash

# Update "dev" Go dependencies.
go get -modfile=dev_go.mod github.com/CVE-2008-0166/dwklint/v2@main
go get -modfile=dev_go.mod github.com/titanous/rocacheck@master
go get -modfile=dev_go.mod github.com/zmap/zlint/v3@master
go get -modfile=dev_go.mod -u
go mod tidy -modfile=dev_go.mod

# Track the Go toolchain version used to run this update in the go directive.
go mod edit -modfile=dev_go.mod -go=$(go env GOVERSION | sed 's/^go//')

# Keep the Dockerfile's golang builder image in step with the go directive.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
"$SCRIPT_DIR/update_go_base_image.sh"

# Add other non-Go dependencies, which "go mod tidy" will have removed.
go get -modfile=dev_go.mod github.com/badkeys/badkeys@main
go get -modfile=dev_go.mod github.com/certlint/certlint@master
go get -modfile=dev_go.mod github.com/CVE-2008-0166/dwk_blocklists_sqlite3@main
go get -modfile=dev_go.mod github.com/rspeer/python-ftfy@main
go get -modfile=dev_go.mod github.com/digicert/pkilint@main
go get -modfile=dev_go.mod github.com/kroeckx/x509lint@master
