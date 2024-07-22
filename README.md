# pkimetal [![Go Report](https://goreportcard.com/badge/github.com/pkimetal/pkimetal)](https://goreportcard.com/report/github.com/pkimetal/pkimetal)

A REST API and web interface that integrates multiple linters to perform pre- and post-issuance linting of Certificates, Precertificates, CRLs, and OCSP Responses.

At a glance:

- [Features](#features)
- [Why lint?](#why-lint)
- [Why use multiple linters?](#why-use-multiple-linters)
- [Why use pkimetal?](#why-use-pkimetal)
- [Supported linters](#supported-linters)
- [Docker containers](#docker-containers)
- [Public instances](#public-instances)
- [About this project](#about-this-project)

Details:

- [Installation and Configuration](doc/INSTALL.md)
- [REST API Documentation](doc/REST_API.md)

## Features

- Access multiple linters via a single, simple REST API call.
- Accepts Certificates, Precertificates, CRLs, and OCSP responses as inputs.
- Enables pre-issuance and post-issuance linting.
- Optionally auto-detects the intended profile of the input.
- Runs only the appropriate linters/lints for the selected profile.
- Unifies the linters' findings into a common response format.
- Optimized for performance and scalability.
- Dockerized.

## Why lint?

CABForum Ballot SC-75, adopted June 27th 2024, explains that...

> Due to the complexity involved in implementing Certificate Profiles that conform to these Requirements, it is considered best practice for the CA to implement a Linting process to test the technical conformity of each to-be-signed artifact prior to signing it.

## Why use multiple linters?

Linters are not in competition with each other. Different linters cover different certificate types, and no linter today claims 100% coverage of all the rules coming from the various root program policies, CABForum requirements, and RFCs. Running multiple linters could well increase your total coverage. If a linter catches even a single issue that no other linter catches, then that linter has proven its worth. Linters, like all software, sometimes have bugs; but it's relatively unlikely that the same bug affects all the linters.

In addition to certificate linters, there are other tools available that can extend your overall linting coverage. These special-purpose linters have a detailed focus on a particular requirement or subset of requirements.

## Why use pkimetal?

- Software integration: Linters have been developed in several different programming languages: Ruby (Certlint), C (x509lint), Go (ZLint), Python (pkilint). It's not always easy to integrate third-party code written in a different language into your own application. **pkimetal does this integration so that you don't have to**.
- To-be-signed input: Certificate linters tend to only accept signed certificates as input, whereas pre-issuance linting is performed on a to-be-signed certificate prior to signing. Figuring out how to convert to-be-signed input into something that the linters can process is sufficiently non-obvious that CABForum Ballot SC-75 includes two suggested methods. **pkimetal accepts to-be-signed input and handles this conversion for you**.
- Lint selection: Getting the correct linting result for any given input type requires calling the right subset of linters with the right options. **pkimetal takes care of this for you**.
- Performance: Most of the available linters are designed to be run from the command line, linting one certificate each time. With some linters this can incur some pretty severe performance penalties: the overhead of starting up the programming language interpreter, and the overhead of initiating the linter functionality. In some cases it can take half a second to lint just one certificate, which would be a bottleneck for many CAs' certificate issuance rates. **pkimetal only incurs these performance penalties once; linting multiple certificates is up to 20x faster!**
- Scalability: Even 20x faster might not be enough for some high-volume certificate issuers. **pkimetal can run multiple instances of most linters, taking advantage of multiple CPU cores**.

Every WebPKI CA is now expected to implement pre-issuance linting. The availability of pkimetal ensures that no CA should struggle to meet this expectation.

## Supported linters

Certificate linters:
- [certlint](https://github.com/certlint/certlint)
- [pkilint](https://github.com/digicert/pkilint)
- [x509lint](https://github.com/kroeckx/x509lint)
- [zlint](https://github.com/zmap/zlint)

Special-purpose linters:
- [dwklint](https://github.com/CVE-2008-0166/dwklint)
- [ftfy](https://github.com/rspeer/python-ftfy)

## Docker containers

[Docker containers](https://github.com/pkimetal/pkimetal/pkgs/container/pkimetal) are pre-built automatically and published on the Github Container Repository (GHCR). Two different release cycles are provided:

- Stable releases: These have a "vX.X.X" tag on GHCR and are automatically built and published whenever a corresponding [pkimetal release](https://github.com/pkimetal/pkimetal/releases) is created. The most recent Stable release also receives the "latest" tag. Since Stable releases track versioned releases of each linter project (wherever possible), **only Stable releases are recommended for production usage**.
- Development releases: These have a "dev.{timestamp}" tag on GHCR and are automatically built and published whenever a corresponding [commit](https://github.com/pkimetal/pkimetal/commits/main/) is pushed to the "main" branch. Since Development releases track the latest commits to the "main"/"master" branch of each linter project, they are NOT RECOMMENDED for production usage.

## Public instances

Sectigo provides public instances of pkimetal that correspond to the two release cycles:

- Stable: https://pkimet.al/
- Development: https://dev.pkimet.al/

These public instances are provided as-is, on a best effort basis. They are NOT RECOMMENDED for production usage by CAs, because (due to Ballot SC-75) they would be seen as Delegated Third Parties. An on-premise deployment of the [Docker container](#docker-containers) for the latest Stable release is the appropriate way to deploy pkimetal in a production CA environment.

## About this project

pkimetal was created by [Rob Stradling](https://github.com/robstradling) at Sectigo, and the project is currently maintained at Sectigo by Rob Stradling and [Martijn Katerbarg](https://github.com/XolphinMartijn). It is hoped that other publicly-trusted CAs and ecosystem participants will benefit and collaborate on future development. :-)

The "metal" suffix was chosen for its double-meaning: it's both an abbreviation of "meta-linter" and it conveys the idea that linting strengthens the PKI!
