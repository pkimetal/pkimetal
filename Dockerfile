# BUILD.
FROM docker.io/library/golang:1.22.5-alpine as build

# Install build dependencies.
RUN apk add --no-cache --update \
	# Common.
	gcc git g++ make \
	# certlint.
	ruby ruby-dev \
	# x509lint.
	openssl-dev

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
ENV GOPATH /app
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
	pipx python3

# Install certlint.
COPY --from=build /usr/local/certlint /usr/local/certlint
RUN gem install public_suffix simpleidn

# Copy dwk_blocklists.
COPY --from=build /usr/local/dwk_blocklists /usr/local/dwk_blocklists

# Install ftfy and pkilint (most recent releases).
ENV PYTHONUNBUFFERED=1
RUN pipx install ftfy pkilint

# pkimetal.
COPY --from=build /app/pkimetal /app/pkimetal
CMD ["/app/pkimetal"]
