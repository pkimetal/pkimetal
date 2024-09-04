# BUILD.
FROM docker.io/library/golang:1.23.0-alpine AS build

# Install build dependencies.
RUN apk add --no-cache --update \
	# Common.
	gcc git g++ make \
	# certlint.
	ruby ruby-dev \
	# x509lint.
	openssl-dev \
    # pkilint.
    curl gcc musl-dev

# Build & install rust + cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN . "$HOME/.cargo/env"

# Clone dwk_blocklists (used by dwklint).
WORKDIR /usr/local
RUN git clone https://github.com/CVE-2008-0166/dwk_blocklists && \
# Clone and build certlint (most recent tag).
	git clone https://github.com/certlint/certlint
WORKDIR /usr/local/certlint
RUN git checkout $(git describe --tags $(git rev-list --tags --max-count=1))
WORKDIR /usr/local/certlint/ext
RUN ruby extconf.rb && \
	make

# Clone and prepare x509lint (no tags, so most recent commit).
WORKDIR /app/linter/x509lint
RUN git clone https://github.com/kroeckx/x509lint && \
	cd x509lint && \
	cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h ..

# Build pkimetal.
WORKDIR /app
COPY . .
RUN git fetch --unshallow
ENV GOPATH=/app
RUN CGO_ENABLED=1 GOOS=linux go build -o pkimetal -ldflags " \
	-X github.com/pkimetal/pkimetal/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
	-X github.com/pkimetal/pkimetal/config.PkimetalVersion=`git describe --tags --always` \
	-X github.com/pkimetal/pkimetal/linter/certlint.GitDescribeTagsAlways=`cd /usr/local/certlint && git describe --tags --always` \
	-X github.com/pkimetal/pkimetal/linter/certlint.RubyDir=/usr/local/certlint \
	-X github.com/pkimetal/pkimetal/linter/x509lint.GitDescribeTagsAlways=`cd /app/linter/x509lint/x509lint && git describe --tags --always`" /app/.


# RUNTIME.
FROM alpine:edge AS runtime

# Install runtime dependencies.
RUN apk add --no-cache --update \
	# Certlint.
	ruby \
	# pkilint and ftfy.
	pipx python3 curl gcc musl-dev

# Build & install rust + cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN . "$HOME/.cargo/env"

# Install certlint.
COPY --from=build /usr/local/certlint /usr/local/certlint
RUN gem install public_suffix simpleidn

# Copy dwk_blocklists.
COPY --from=build /usr/local/dwk_blocklists /usr/local/dwk_blocklists

# Install ftfy and pkilint (most recent releases).
ENV PYTHONUNBUFFERED=1
RUN pipx install ftfy pkilint

# pkimetal.
WORKDIR /app
RUN wget https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2 && \
	wget -O finding_metadata.csv.smime https://raw.githubusercontent.com/digicert/pkilint/main/pkilint/cabf/smime/finding_metadata.csv && \
	wget -O finding_metadata.csv.serverauth https://raw.githubusercontent.com/digicert/pkilint/main/pkilint/cabf/serverauth/finding_metadata.csv && \
	wget -O finding_metadata.csv.etsi https://raw.githubusercontent.com/digicert/pkilint/main/pkilint/etsi/finding_metadata.csv
COPY --from=build /app/pkimetal /app/pkimetal
CMD ["/app/pkimetal"]
