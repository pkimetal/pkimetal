#!/bin/bash

# Update "stable" Go dependencies.
go get -u
go mod tidy

# Add other non-Go dependencies, which "go mod tidy" will have removed.
go get github.com/badkeys/badkeys
go get github.com/certlint/certlint
go get github.com/CVE-2008-0166/dwk_blocklists_sqlite3
go get github.com/rspeer/python-ftfy
go get github.com/digicert/pkilint
go get github.com/kroeckx/x509lint
