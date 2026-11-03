#!/bin/bash

# Non-Go dependencies, which are tracked in go.mod (and used by the Dockerfile)
# but are removed by "go mod tidy" because no Go code imports them.
NON_GO_MODULES=(
	github.com/badkeys/badkeys
	github.com/certlint/certlint
	github.com/CVE-2008-0166/dwk_blocklists_sqlite3
	github.com/rspeer/python-ftfy
	github.com/digicert/pkilint
	github.com/google/paranoid_crypto
	github.com/kroeckx/x509lint
)

# Update "stable" Go dependencies.
go get -u

# Save the non-Go dependencies' current requirements and checksums, so that
# they can be restored after "go mod tidy".
declare -A PINNED_VERSIONS PINNED_SUMS
for module in "${NON_GO_MODULES[@]}"; do
	PINNED_VERSIONS[$module]=$(awk -v m="$module" '$1 == m { print $2; exit }' go.mod)
	PINNED_SUMS[$module]=$(awk -v m="$module" -v v="${PINNED_VERSIONS[$module]}" '$1 == m && ($2 == v || $2 == v "/go.mod")' go.sum)
done

go mod tidy

# Restore the non-Go dependencies' requirements and checksums.  With the checksums
# restored, "go get" does not need to consult the checksum database.
for module in "${NON_GO_MODULES[@]}"; do
	if [ -n "${PINNED_VERSIONS[$module]}" ]; then
		[ -n "${PINNED_SUMS[$module]}" ] && echo "${PINNED_SUMS[$module]}" >> go.sum
		go get -modfile=go.mod "$module@${PINNED_VERSIONS[$module]}"
	fi
done
# Re-sort go.sum (by module path, then version), as "go" itself would.
LC_ALL=C sort -s -k1,1 -k2,2V -o go.sum go.sum

# Track the Go toolchain version used to run this update in the go directive.
go mod edit -go=$(go env GOVERSION | sed 's/^go//')

# Keep the Dockerfile's golang builder image in step with the go directive.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
"$SCRIPT_DIR/update_go_base_image.sh"

# Upgrade the non-Go dependencies to their latest versions.  Without an explicit
# version, "go get" never downgrades; and if a newer version cannot be fetched or
# verified (e.g. because the Go module mirror or checksum database is missing
# it), "go get" fails without changing go.mod, so the restored pin is kept.
# The redundant "-modfile=go.mod" (go.mod is already the default) keeps OpenSSF
# Scorecard's Pinned-Dependencies parser from flagging these intentional
# fetch-latest calls; go.mod/go.sum still pin the resolved versions by hash.
go get -modfile=go.mod github.com/badkeys/badkeys
go get -modfile=go.mod github.com/certlint/certlint
go get -modfile=go.mod github.com/CVE-2008-0166/dwk_blocklists_sqlite3
go get -modfile=go.mod github.com/rspeer/python-ftfy
go get -modfile=go.mod github.com/digicert/pkilint
go get -modfile=go.mod github.com/google/paranoid_crypto
go get -modfile=go.mod github.com/kroeckx/x509lint
