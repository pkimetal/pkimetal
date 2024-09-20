# BUILD.
FROM docker.io/library/golang:1.23.1-alpine AS build
ARG gomodfile

# Install build dependencies.
RUN apk add --no-cache --update \
	# Common.
	gcc git g++ make \
	# certlint.
	ruby ruby-dev \
	# ftfy and pkilint.
	pipx \
	# pkilint (for pyasn1-fasder).
	rustup \
	# x509lint.
	openssl-dev

# Configure environment.
ENV PATH="/root/.local/bin:/root/.cargo/bin:${PATH}"

# Build dependencies.
WORKDIR /app
COPY . .
RUN git fetch --unshallow | echo && \
	# Fetch repositories.
	mkdir /usr/local/build && \
	mkdir /usr/local/pkimetal && \
	go get -modfile=$gomodfile github.com/certlint/certlint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/certlint/certlint) /usr/local/pkimetal/certlint/ && \
	go get -modfile=$gomodfile github.com/CVE-2008-0166/dwk_blocklists && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/CVE-2008-0166/dwk_blocklists) /usr/local/pkimetal/dwk_blocklists/ && \
	go get -modfile=$gomodfile github.com/rspeer/python-ftfy && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/rspeer/python-ftfy) /usr/local/build/ftfy/ && \
	go get -modfile=$gomodfile github.com/digicert/pkilint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/digicert/pkilint) /usr/local/build/pkilint/ && \
	go get -modfile=$gomodfile github.com/kroeckx/x509lint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/kroeckx/x509lint) /usr/local/build/x509lint/ && \
	wget https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2 && \
	# Build certlint.
	cd /usr/local/pkimetal/certlint/ext && \
	ruby extconf.rb && \
	make && \
	# Build ftfy wheel.
	cd /usr/local/build/ftfy && \
	pipx install poetry && \
	pipx inject poetry poetry-plugin-bundle && \
	poetry bundle venv --python=/usr/bin/python3 --only=main /usr/local/pkimetal/ftfy && \
	# Install rust + cargo using rustup (for pyasn1-fasder).
	rustup-init -y && \
	source "$HOME/.cargo/env" && \
	# Build pkilint wheel.
	cd /usr/local/build/pkilint && \
	cp /app/linter/pkilint/pyproject.toml . && \
	poetry bundle venv --python=/usr/bin/python3 --only=main /usr/local/pkimetal/pkilint && \
	cp pkilint/cabf/smime/finding_metadata.csv /app/finding_metadata.csv.smime && \
	cp pkilint/cabf/serverauth/finding_metadata.csv /app/finding_metadata.csv.serverauth && \
	cp pkilint/etsi/finding_metadata.csv /app/finding_metadata.csv.etsi && \
	# Prepare x509lint.
	cd /usr/local/build/x509lint && \
	cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h /app/linter/x509lint && \
	# Build pkimetal.
	cd /app && \
	CGO_ENABLED=1 GOOS=linux go build -modfile=$gomodfile -o pkimetal -ldflags " \
	-X github.com/pkimetal/pkimetal/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
	-X github.com/pkimetal/pkimetal/config.PkimetalVersion=`git describe --tags --always` \
	-X github.com/pkimetal/pkimetal/linter/certlint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/certlint/certlint | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/certlint.RubyDir=/usr/local/pkimetal/certlint \
	-X github.com/pkimetal/pkimetal/linter/dwklint.BlocklistDir=/usr/local/pkimetal/dwk_blocklists \
	-X github.com/pkimetal/pkimetal/linter/ftfy.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/rspeer/python-ftfy | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/ftfy.PythonDir=`find /usr/local/pkimetal/ftfy/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/pkilint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/digicert/pkilint | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/pkilint.PythonDir=`find /usr/local/pkimetal/pkilint/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/x509lint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/kroeckx/x509lint | sed 's/+incompatible//g'`" /app/.


# RUNTIME.
FROM alpine:edge AS runtime

# Install runtime dependencies.
COPY --from=build /usr/local/pkimetal /usr/local/pkimetal
RUN apk add --no-cache --update \
	# pkilint and ftfy.
	python3 \
	# certlint.
	ruby && \
	gem install public_suffix simpleidn

# Install pkimetal.
WORKDIR /app
COPY --from=build /app/pkimetal /app/AllCertificateRecordsCSVFormatv2 /app/finding_metadata.csv.* /app/
CMD ["/app/pkimetal"]
