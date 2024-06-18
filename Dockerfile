# BUILD.
FROM docker.io/library/golang:1.22.4-alpine as build

# Install build dependencies.
RUN apk add --no-cache --update \
	# Common.
	gcc git g++ make \
	# Certlint.
	ruby ruby-dev \
	# x509lint.
	openssl-dev

# Clone dwk_blocklists (used by dwklint).
WORKDIR /usr/local
RUN git clone https://github.com/CVE-2008-0166/dwk_blocklists && \
# Clone and build Certlint.
	git clone https://github.com/certlint/certlint
WORKDIR /usr/local/certlint/ext
RUN ruby extconf.rb && \
	make

# Clone and prepare x509lint.
WORKDIR /app/linter/x509lint
RUN git clone https://github.com/kroeckx/x509lint
WORKDIR /app/linter/x509lint/x509lint
RUN git rev-parse HEAD > ../x509lint_vcs_revision && \
	cp asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h ..

# Build pkimetal.
WORKDIR /app
COPY . .
ENV GOPATH /app
RUN CGO_ENABLED=1 GOOS=linux go build -o pkimetal -ldflags "-X github.com/pkimetal/pkimetal/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` -X github.com/pkimetal/pkimetal/config.PkimetalVersion=`git describe --tags` -X github.com/pkimetal/pkimetal/linter/x509lint.VcsRevision=`cat linter/x509lint/x509lint_vcs_revision`" /app/.


# RUNTIME.
FROM alpine:edge AS runtime

# Install runtime dependencies.
RUN apk add --no-cache --update \
	# Certlint.
	ruby \
	# pkilint and FTFY.
	pipx python3

# Install Certlint.
COPY --from=build /usr/local/certlint /usr/local/certlint
RUN gem install public_suffix simpleidn

# Copy dwk_blocklists.
COPY --from=build /usr/local/dwk_blocklists /usr/local/dwk_blocklists

# Install pkilint and FTFY.
ENV PYTHONUNBUFFERED=1
RUN pipx install pkilint ftfy

# pkimetal.
COPY --from=build /app/pkimetal /app/pkimetal
CMD ["/app/pkimetal"]
