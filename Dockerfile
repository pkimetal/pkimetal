# BUILD.
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build

# Install build dependencies.
RUN apk add --no-cache busybox && \
	apk add --no-cache --update \
	# Common.
	binutils g++ gcc git make musl-dev pkgconfig \
	# badkeys (for rsakeys/fermat.py).
	gmp-dev mpfr-dev mpc1-dev python3-dev \
	# badkeys, ftfy, and pkilint.
	pipx \
	# certlint.
	ruby ruby-dev \
	# pkilint (for pyasn1-fasder).
	rustup \
	# paranoid (lattice checks and protobuf generation).
	fplll-dev protobuf \
	# x509lint.
	openssl-dev

# Configure environment.
ENV PATH="/root/.local/bin:/root/.cargo/bin:${PATH}"

# Build dependencies.
WORKDIR /app
COPY . .
ARG gomodfile=go.mod
RUN \
	# Fetch repositories.  These modules are pinned in $gomodfile, so use
	# "go mod download" (which honours those pinned versions) rather than
	# "go get" (which would resolve/upgrade to the latest available version).
	mkdir /usr/local/build && \
	mkdir /usr/local/pkimetal && \
	go mod download -modfile=$gomodfile github.com/badkeys/badkeys && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/badkeys/badkeys) /usr/local/build/badkeys/ && \
	go mod download -modfile=$gomodfile github.com/certlint/certlint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/certlint/certlint) /usr/local/pkimetal/certlint/ && \
	go mod download -modfile=$gomodfile github.com/CVE-2008-0166/dwk_blocklists_sqlite3 && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/CVE-2008-0166/dwk_blocklists_sqlite3) /usr/local/pkimetal/dwk_blocklists_sqlite3/ && \
	go mod download -modfile=$gomodfile github.com/rspeer/python-ftfy && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/rspeer/python-ftfy) /usr/local/build/ftfy/ && \
	go mod download -modfile=$gomodfile github.com/digicert/pkilint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/digicert/pkilint) /usr/local/build/pkilint/ && \
	go mod download -modfile=$gomodfile github.com/google/paranoid_crypto && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/google/paranoid_crypto) /usr/local/build/paranoid/ && \
	go mod download -modfile=$gomodfile github.com/kroeckx/x509lint && \
	cp -R $(go list -modfile=$gomodfile -m -f '{{.Dir}}' github.com/kroeckx/x509lint) /usr/local/build/x509lint/ && \
	# Install poetry (for building Python-based linters).
	pipx install poetry && \
	pipx inject poetry poetry-plugin-bundle && \
	# Configure package versions for each Python-based linter.
	sed -i "s/_VERSION_/`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/badkeys/badkeys | sed 's/[-+].*//g'`/g" /app/linter/badkeys/pyproject.toml && \
	sed -i "s/_VERSION_/`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/rspeer/python-ftfy | sed 's/[-+].*//g'`/g" /app/linter/ftfy/pyproject.toml && \
	sed -i "s/_VERSION_/`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/digicert/pkilint | sed 's/[-+].*//g'`/g" /app/linter/pkilint/pyproject.toml && \
	# Build badkeys and update its blocklist.
	cd /usr/local/build/badkeys && \
	cp /app/linter/badkeys/pyproject.toml . && \
	poetry lock && \
	poetry bundle venv --python=/usr/bin/python3 --only=main /usr/local/pkimetal/badkeys && \
	/usr/local/pkimetal/badkeys/bin/python3 badkeys-cli --update-bl && \
	# Build certlint.
	cd /usr/local/pkimetal/certlint/ext && \
	ruby extconf.rb && \
	make && \
	# Build ftfy wheel.
	cd /usr/local/build/ftfy && \
	cp /app/linter/ftfy/pyproject.toml . && \
	poetry lock && \
	poetry bundle venv --python=/usr/bin/python3 --only=main /usr/local/pkimetal/ftfy && \
	# Build paranoid's key/signature checks (the optional randomness extension is not used).
	cd /usr/local/build/paranoid && \
	protoc -I. --python_out=. paranoid_crypto/paranoid.proto paranoid_crypto/lib/data/data.proto && \
	cp /app/linter/paranoid/pyproject.toml . && \
	poetry lock && \
	poetry bundle venv --python=/usr/bin/python3 --only=main /usr/local/pkimetal/paranoid && \
	find /usr/local/pkimetal/paranoid/lib/python*/site-packages -type f -name '*.so*' -exec strip --strip-unneeded {} + && \
	find /usr/local/pkimetal/paranoid/lib/python*/site-packages -type d -name tests -prune -exec rm -rf {} + && \
	rm -rf /usr/local/pkimetal/paranoid/lib/python*/site-packages/pip \
		/usr/local/pkimetal/paranoid/lib/python*/site-packages/pip-*.dist-info \
		/usr/local/pkimetal/paranoid/bin/pip* && \
	# Install rust + cargo using rustup (for pyasn1-fasder).
	rustup-init -y && \
	source "$HOME/.cargo/env" && \
	# Build pkilint wheel.
	cd /usr/local/build/pkilint && \
	cp /app/linter/pkilint/pyproject.toml . && \
	poetry lock && \
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
	-X github.com/pkimetal/pkimetal/linter/badkeys.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/badkeys/badkeys | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/badkeys.PythonDir=`find /usr/local/pkimetal/badkeys/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/certlint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/certlint/certlint | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/certlint.RubyDir=/usr/local/pkimetal/certlint \
	-X github.com/pkimetal/pkimetal/linter/dwklint.BlocklistDBPath=/usr/local/pkimetal/dwk_blocklists_sqlite3/dwk_blocklists.sqlite3 \
	-X github.com/pkimetal/pkimetal/linter/ftfy.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/rspeer/python-ftfy | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/ftfy.PythonDir=`find /usr/local/pkimetal/ftfy/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/paranoid.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/google/paranoid_crypto` \
	-X github.com/pkimetal/pkimetal/linter/paranoid.PythonDir=`find /usr/local/pkimetal/paranoid/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/pkilint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/digicert/pkilint | sed 's/+incompatible//g'` \
	-X github.com/pkimetal/pkimetal/linter/pkilint.PythonDir=`find /usr/local/pkimetal/pkilint/lib/python*/site-packages -maxdepth 0` \
	-X github.com/pkimetal/pkimetal/linter/x509lint.Version=`go list -modfile=$gomodfile -m -f '{{.Version}}' github.com/kroeckx/x509lint | sed 's/+incompatible//g'`" /app/.


# RUNTIME.
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS runtime

# Configure environment.
CMD ["/app/pkimetal"]
ENV HOME=/usr/local/pkimetal
WORKDIR /app

# Install runtime dependencies.
RUN apk add --no-cache --update \
	# badkeys (for rsakeys/fermat.py).
	gmp mpfr mpc1 \
	# certlint.
	openssl ruby \
	# badkeys, ftfy, paranoid, and pkilint.
	python3 && \
	# certlint.
	gem install base64 public_suffix simpleidn && \
	# badkeys.
	adduser -D -u 1001 --home /usr/local/pkimetal pkimetal && \
	chgrp -R 0 /usr/local/pkimetal && \
	chmod -R g=u /usr/local/pkimetal

# Copy build assets.
COPY --from=build /root/.cache/badkeys /usr/local/pkimetal/.cache/badkeys
USER 1001
COPY --from=build /usr/local/pkimetal /usr/local/pkimetal
COPY --from=build /app/pkimetal /app/finding_metadata.csv.* /app/
