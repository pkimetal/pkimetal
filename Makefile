all: clean pkimetal

clean: clean_x509lint
	rm -f pkimetal

pkimetal: fetch_x509lint
	CGO_ENABLED=1 GOOS=linux go build -o $@ -ldflags "-X github.com/pkimetal/pkimetal/config.BuildTimestamp=$(shell date --utc +%Y-%m-%dT%H:%M:%SZ) -X github.com/pkimetal/pkimetal/config.PkimetalVersion=$(shell git describe --tags) -X github.com/pkimetal/pkimetal/linter/x509lint.VcsRevision=$(shell cat linter/x509lint/x509lint_vcs_revision)"

fetch_x509lint:
	cd linter/x509lint; \
		git clone https://github.com/kroeckx/x509lint; \
		cd x509lint; \
		git rev-parse HEAD > ../x509lint_vcs_revision; \
		cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h ..; \
		cd ..; \
		rm -rf x509lint

clean_x509lint:
	cd linter/x509lint; \
		rm -f asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h x509lint_vcs_revision
