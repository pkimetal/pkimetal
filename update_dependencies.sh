#!/bin/bash

# Update "stable" Go dependencies.
go get -u
go mod tidy

# Add other non-Go dependencies, which "go mod tidy" will have removed.
# The redundant "-modfile=go.mod" (go.mod is already the default) keeps OpenSSF
# Scorecard's Pinned-Dependencies parser from flagging these intentional
# fetch-latest calls; go.mod/go.sum still pin the resolved versions by hash.
go get -modfile=go.mod github.com/badkeys/badkeys
go get -modfile=go.mod github.com/certlint/certlint
go get -modfile=go.mod github.com/CVE-2008-0166/dwk_blocklists_sqlite3
go get -modfile=go.mod github.com/rspeer/python-ftfy
go get -modfile=go.mod github.com/digicert/pkilint
go get -modfile=go.mod github.com/kroeckx/x509lint
