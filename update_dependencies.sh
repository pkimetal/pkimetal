#!/bin/bash

# Update "dev" Go dependencies.
go get -modfile=dev_go.mod github.com/CVE-2008-0166/dwklint@main
go get -modfile=dev_go.mod github.com/zmap/zlint/v3@master
go get -modfile=dev_go.mod -u
go mod tidy -modfile=dev_go.mod

# Update "stable" Go dependencies.
go get -u
go mod tidy
