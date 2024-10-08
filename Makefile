pkimetal: clean
	CURDIR=$(shell pwd)
	cd $(shell go list -m -f {{.Dir}} github.com/kroeckx/x509lint); \
		cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h $(CURDIR)/linter/x509lint
	CGO_ENABLED=1 GOOS=linux go build -o $@ -ldflags " \
	-X github.com/pkimetal/pkimetal/config.BuildTimestamp=$(shell date --utc +%Y-%m-%dT%H:%M:%SZ) \
	-X github.com/pkimetal/pkimetal/config.PkimetalVersion=$(shell git describe --tags --always) \
	-X github.com/pkimetal/pkimetal/linter/x509lint.Version=$(shell go list -m -f {{.Version}} github.com/kroeckx/x509lint)"
	make clean_x509lint

pkimetal-dev: clean
	CURDIR=$(shell pwd)
	cd $(shell go list -modfile=dev_go.mod -m -f {{.Dir}} github.com/kroeckx/x509lint); \
		cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h $(CURDIR)/linter/x509lint
	CGO_ENABLED=1 GOOS=linux go build -modfile=dev_go.mod -o $@ -ldflags " \
	-X github.com/pkimetal/pkimetal/config.BuildTimestamp=$(shell date --utc +%Y-%m-%dT%H:%M:%SZ) \
	-X github.com/pkimetal/pkimetal/config.PkimetalVersion=$(shell git describe --tags --always) \
	-X github.com/pkimetal/pkimetal/linter/x509lint.Version=$(shell go list -modfile=dev_go.mod -m -f {{.Version}} github.com/kroeckx/x509lint)"
	make clean_x509lint
	mv pkimetal-dev pkimetal

clean: clean_x509lint
	rm -f pkimetal

clean_x509lint:
	cd linter/x509lint; \
		rm -f asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h
