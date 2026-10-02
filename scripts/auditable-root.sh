#!/bin/bash
# Read the cargo-auditable crate list and require exactly one root package.
# Usage: auditable-root.sh PACKAGE BINARY [PACKAGE BINARY...]
# rust-audit-info and python3 must be on PATH.
set -euo pipefail
if [[ $# -lt 2 || $(($# % 2)) -ne 0 ]]; then
    echo 'usage: auditable-root.sh PACKAGE BINARY [PACKAGE BINARY...]' >&2
    exit 2
fi
while [[ $# -ge 2 ]]; do
    package=$1
    binary=$2
    shift 2
    json=$(rust-audit-info "$binary")
    printf '%s' "$json" | python3 -c '
import json
import sys
info = json.load(sys.stdin)
roots = [pkg["name"] for pkg in info["packages"] if pkg.get("root") is True]
want = sys.argv[1]
path = sys.argv[2]
if roots != [want]:
    sys.stderr.write("auditable root for %s is %s, want %s\n" % (path, roots, want))
    raise SystemExit(1)
' "$package" "$binary"
done
