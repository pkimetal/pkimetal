# pkimetal [![Go Report](https://goreportcard.com/badge/github.com/pkimetal/pkimetal)](https://goreportcard.com/report/github.com/pkimetal/pkimetal)

A REST API and web interface that integrates multiple linters to perform pre- and post-issuance linting of PKI artifacts (Certificates, Precertificates, CRLs, and OCSP Responses).

At a glance:

- [Features](#features)
- [Why lint?](#why-lint)
- [Why use multiple linters?](#why-use-multiple-linters)
- [Why use pkimetal?](#why-use-pkimetal)
- [Supported linters](#supported-linters)
- [Docker containers](#docker-containers)
- [Public instances](#public-instances)
- [Known users/integrations](#known-usersintegrations)
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

CABForum Ballot [SC-75](https://github.com/cabforum/servercert/pull/527/files#diff-e0ac1bd190515a4f2ec09139d395ef6a8c7e9e5b612957c1f5a2dea80c6a6cfeR1114), adopted June 27th 2024, explains that...

> Due to the complexity involved in implementing Certificate Profiles that conform to these Requirements, it is considered best practice for the CA to implement a Linting process to test the technical conformity of each to-be-signed artifact prior to signing it.

## Why use multiple linters?

Linters are not in competition with each other. Different linters have different capabilities, and no linter today claims 100% coverage of all the rules coming from the various root program policies, CABForum requirements, RFCs, etc. Running multiple linters will probably increase your total coverage. If a linter catches even a single issue that no other linter catches, then that linter has proven its worth. Linters, like all software, sometimes have bugs; but it's relatively unlikely that the same bug affects all the linters.

In addition to general-purpose linters for PKI artifacts, there are also special-purpose linters available that can extend your overall linting coverage with a detailed focus on a particular requirement or subset of requirements.

## Why use pkimetal?

- Software integration: Linters have been developed in several different programming languages: Ruby (Certlint), C (x509lint), Go (ZLint), Python (pkilint). It's not always easy to integrate third-party code written in a different language into your own application. **pkimetal does this integration so that you don't have to**.
- To-be-signed input: Linters tend to only accept signed PKI artifacts as input, whereas pre-issuance linting is performed on a to-be-signed artifact prior to signing. Figuring out how to convert to-be-signed input into something that the linters can process is sufficiently non-obvious that CABForum Ballot SC-75 includes two [suggested](https://github.com/cabforum/servercert/pull/527/files#diff-e0ac1bd190515a4f2ec09139d395ef6a8c7e9e5b612957c1f5a2dea80c6a6cfeR1120) [methods](https://github.com/cabforum/servercert/pull/527/files#diff-e0ac1bd190515a4f2ec09139d395ef6a8c7e9e5b612957c1f5a2dea80c6a6cfeR1121). **pkimetal accepts to-be-signed input and handles this conversion for you**.
- Lint selection: Getting the correct linting result for any given input type requires calling the right subset of linters with the right options. **pkimetal takes care of this for you**.
- Performance: Most of the available linters are designed to be run from the command line, linting one input file each time. With some linters, repeating this process for multiple files can incur some pretty severe performance penalties: the overhead of starting up the programming language interpreter each time, and the overhead of initiating the linter functionality each time. These overheads mean that, for example, it can take half a second to lint just one certificate, which would be a bottleneck for many CAs' certificate issuance rates. **pkimetal incurs these performance penalties only once, making the linting of multiple PKI artifacts up to 20x faster!**
- Scalability: Even 20x faster might not be enough for some high-volume certificate issuers. **pkimetal can run multiple instances of most linters, taking advantage of multiple CPU cores**.

Every WebPKI CA is now expected to implement pre-issuance certificate linting. The availability of pkimetal ensures that no CA should struggle to meet this expectation.

## Supported linters

General-purpose linters:
- [certlint](https://github.com/certlint/certlint): Certificate linter (CABForum TLS; RFC5280).
- [pkilint](https://github.com/digicert/pkilint): Certificate, CRL, and OCSP response linter (CABForum TLS and S/MIME; ETSI EN 319 412 and TS 119 495; RFC5280).
- [x509lint](https://github.com/kroeckx/x509lint): Certificate linter (CABForum TLS; RFC5280).
- [zlint](https://github.com/zmap/zlint): Certificate and CRL linter (CABForum TLS, S/MIME, and Code Signing; ETSI EN 319 412 and TS 119 495; RFC5280).

Special-purpose linters:
- [badkeys](https://github.com/badkeys/badkeys): Detects various public key vulnerabilities.
- [dwklint](https://github.com/CVE-2008-0166/dwklint): Detects Debian weak keys (CVE-2008-0166), as required by CABForum Ballot [SC-73](https://github.com/cabforum/servercert/pull/500/files#diff-e0ac1bd190515a4f2ec09139d395ef6a8c7e9e5b612957c1f5a2dea80c6a6cfeR1705).
- [ftfy](https://github.com/rspeer/python-ftfy): Detects mojibake (character encoding mix-ups).
- [pwnedkeys](https://pwnedkeys.com): Detects compromised keys, where the private key was found "in the wild" and reported to the Pwnedkeys service. (NOTE: Since this linter currently involve calling an external API over the internet, it is **disabled by default**; to enable it via an environment variable, set `PKIMETAL_LINTER_PWNEDKEYS_NUMGOROUTINES=<n>` where `<n>` is an integer greater than zero).
- [rocacheck](https://github.com/titanous/rocacheck): Detects ROCA weak keys (CVE-2017-15361), as required by CABForum Ballot [SC-73](https://github.com/cabforum/servercert/pull/500/files#diff-e0ac1bd190515a4f2ec09139d395ef6a8c7e9e5b612957c1f5a2dea80c6a6cfeR1706).

## Docker containers

[Docker containers](https://github.com/orgs/pkimetal/packages?repo_name=pkimetal) are pre-built automatically and published on the Github Container Repository (GHCR). Two different release cycles are provided:

- [Stable](https://github.com/pkimetal/pkimetal/pkgs/container/pkimetal) releases: These have a "vX.X.X" tag on GHCR and are automatically built and published whenever a corresponding [pkimetal release](https://github.com/pkimetal/pkimetal/releases) is created. The most recent Stable release also receives the "latest" tag. Since Stable releases track versioned releases of each linter project (wherever possible), **only Stable releases are recommended for production usage**.
- [Development](https://github.com/pkimetal/pkimetal/pkgs/container/pkimetal-dev) releases: These have a "YYYYMMDDHHMMSS" tag on GHCR and are automatically built and published whenever a corresponding [commit](https://github.com/pkimetal/pkimetal/commits/main/) is pushed to the "main" branch. Since Development releases also track the latest commits to the "main"/"master" branch of each linter project, they are NOT RECOMMENDED for production usage.

## Public instances

Sectigo provides public instances of pkimetal that correspond to the two release cycles:

- Stable: https://pkimet.al/
- Development: https://dev.pkimet.al/

These public instances are provided as-is, on a best effort basis. They are NOT RECOMMENDED for production usage by CAs, because (due to Ballot SC-75) they may be seen as Delegated Third Parties. Your own deployment of the [Docker container](#docker-containers) for the latest Stable release is the appropriate way to deploy pkimetal in a production CA environment.

## Known users/integrations

Here are some projects/CAs that are known to use or integrate with pkimetal:

- [crt.sh](https://crt.sh) (Sectigo): On-demand certificate linting.
- [EJBCA](https://www.ejbca.org): Post Processing [Validator](https://docs.keyfactor.com/ejbca/latest/pkimetal-validator)
- [Let's Encrypt](https://letsencrypt.org): [Continuous integration](https://github.com/letsencrypt/boulder/pull/8063)
- [pkimet.al](https://pkimet.al) (Sectigo): The two [Public instances](#public-instances) listed above
- [Sectigo](https://sectigo.com/): Pre-issuance linting

Please submit a pull request to update README.md if you are aware of another CA/project that uses or integrates with pkimetal.

## About this project

pkimetal was created by [Rob Stradling](https://github.com/robstradling) at Sectigo, and the project is currently maintained at Sectigo by Rob Stradling and [Martijn Katerbarg](https://github.com/XolphinMartijn). It is hoped that other publicly-trusted CAs and ecosystem participants will benefit and collaborate on future development. :-)

The "metal" suffix was chosen for its double-meaning: it's both an abbreviation of "meta-linter" and it conveys the idea that (meta-)linting strengthens the PKI!

The project's [mascot](https://pkimet.al/mascot.jpg) is a cartoon lint roller pretending to be a brave knight, clad in armour (metal, obviously) to bravely fight the good fight of PKI policy compliance! Standing atop its vanquished foe (a pile of clothes, representing a marauding band of noncompliant TBSCertificates), it proudly displays the battle wounds (linter "findings") sustained during its noble quest. 😉
