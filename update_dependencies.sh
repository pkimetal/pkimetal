#!/bin/bash

# Update "dev" Go dependencies.
go get -modfile=dev_go.mod github.com/CVE-2008-0166/dwklint@main
go get -modfile=dev_go.mod github.com/zmap/zlint/v3@master
go get -modfile=dev_go.mod -u
go mod tidy -modfile=dev_go.mod
# Other non-Go dependencies, which "go mod tidy" would remove.
go get -modfile=dev_go.mod github.com/certlint/certlint@master
go get -modfile=dev_go.mod github.com/rspeer/python-ftfy@main
go get -modfile=dev_go.mod github.com/digicert/pkilint@main
go get -modfile=dev_go.mod github.com/kroeckx/x509lint@master

# Update "stable" Go dependencies.
go get -u
go mod tidy
# Other non-Go dependencies, which "go mod tidy" would remove.
go get github.com/certlint/certlint
go get github.com/rspeer/python-ftfy
go get github.com/digicert/pkilint
go get github.com/kroeckx/x509lint
