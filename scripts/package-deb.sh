#!/usr/bin/env bash
# Builds dist/gatekeep_<version>_<arch>.deb with the binary and a systemd unit.
#   ./scripts/package-deb.sh 0.1.0 amd64
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" -o "$STAGE/usr/bin/gatekeep" "$ROOT/cmd/gatekeep"

install -Dm644 "$ROOT/packaging/gatekeep-demo.service" "$STAGE/lib/systemd/system/gatekeep-demo.service"
install -d "$STAGE/DEBIAN"
cat >"$STAGE/DEBIAN/control" <<EOF
Package: gatekeep
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Aditya Tiwari <at04proguys@gmail.com>
Description: OIDC identity provider and authenticating reverse proxy
 Authorization code + PKCE, rotating refresh tokens with reuse detection,
 JWKS key rotation, token revocation and a JWT-validating TLS reverse proxy.
EOF

mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/gatekeep_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo "built $OUT"
