#!/bin/bash

# Update "dev" Go dependencies.
go get -modfile=dev_go.mod github.com/CVE-2008-0166/dwklint@main
go get -modfile=dev_go.mod github.com/zmap/zlint/v3@master
go get -modfile=dev_go.mod -u
go mod tidy -modfile=dev_go.mod

# Add other non-Go dependencies, which "go mod tidy" will have removed.
go get -modfile=dev_go.mod github.com/certlint/certlint@master
go get -modfile=dev_go.mod github.com/rspeer/python-ftfy@main
go get -modfile=dev_go.mod github.com/digicert/pkilint@main
go get -modfile=dev_go.mod github.com/kroeckx/x509lint@master
