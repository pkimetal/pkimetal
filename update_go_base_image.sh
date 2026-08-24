#!/bin/bash

# Pin the Dockerfile's golang builder image to the Go toolchain that produced
# the go directive, so a module's required Go version and the builder image can
# never drift apart (which would break the build with GOTOOLCHAIN=local on
# Alpine). Only acts when the Go version changes; Alpine-only digest refreshes
# for an unchanged version are left to Dependabot's docker updates.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
dockerfile="$SCRIPT_DIR/Dockerfile"

# Temporary cap: some CI tooling doesn't support Go 1.27 yet.
max_goversion_majmin="1.26"

goversion=$(go env GOVERSION | sed 's/^go//')
current=$(sed -nE 's|^FROM docker\.io/library/golang:([0-9]+(\.[0-9]+)*)-.* AS build$|\1|p' "$dockerfile")

if [ "$current" = "$goversion" ]; then
	exit 0
fi

goseries=$(echo "$goversion" | cut -d. -f1,2)
if [ "$(printf '%s\n%s\n' "$max_goversion_majmin" "$goseries" | sort -V | tail -n1)" != "$max_goversion_majmin" ]; then
	echo "update_go_base_image.sh: skipping Go $goversion; capped at $max_goversion_majmin" >&2
	exit 0
fi

# Preserve the pinned Alpine variant (e.g. "alpine3.24") from the current tag.
variant=$(sed -nE 's|^FROM docker\.io/library/golang:[0-9]+(\.[0-9]+)*-(alpine[0-9.]*).* AS build$|\2|p' "$dockerfile")
if [ -z "$variant" ]; then
	echo "update_go_base_image.sh: could not parse the golang builder image in $dockerfile" >&2
	exit 1
fi

image="docker.io/library/golang:${goversion}-${variant}"
digest=$(docker buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')
if [ -z "$digest" ]; then
	echo "update_go_base_image.sh: could not resolve digest for $image" >&2
	exit 1
fi

sed -i -E "s|(^FROM docker\.io/library/golang:)[^ ]+ (AS build)|\1${goversion}-${variant}@${digest} \2|" "$dockerfile"
echo "update_go_base_image.sh: pinned builder to golang:${goversion}-${variant}@${digest}"
