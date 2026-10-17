#!/usr/bin/env bash
# Walks the whole OIDC flow against a running `gatekeep demo` with nothing but
# curl + openssl: PKCE login, API calls through the proxy, refresh rotation,
# refresh-token reuse detection and revocation.
#
#   ./gatekeep demo -addr :8099 &      # or: make demo
#   ./scripts/demo.sh http://localhost:8099
set -euo pipefail

BASE="${1:-http://localhost:8080}"
BASE="${BASE%/}"
IDP="$BASE/idp"
CLIENT="demo-web"
REDIRECT="$BASE/"
USER_NAME="${GK_USER:-bob}"
USER_PASS="${GK_PASS:-bob-demo-pass}"

pass=0; fail=0
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
check() { # check <description> <expected> <actual>
  if [[ "$2" == "$3" ]]; then green "  PASS  $1 ($3)"; pass=$((pass+1));
  else red "  FAIL  $1: expected $2, got $3"; fail=$((fail+1)); fi
}
need() { command -v "$1" >/dev/null || { red "missing dependency: $1"; exit 1; }; }
need curl; need openssl

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
json_field() { # json_field <name> : crude but dependency-free JSON string extraction
  sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}
api() { # api <path> <token> -> HTTP status
  curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $2" "$BASE/api/$1"
}

echo "== GateKeep demo against $BASE"
curl -sf "$BASE/api/health" >/dev/null || { red "nothing answering at $BASE"; exit 1; }

echo "-- 1. Authorization code + PKCE"
VERIFIER=$(openssl rand 48 | b64url)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | b64url)
STATE=$(openssl rand 16 | b64url)

LOCATION=$(curl -s -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "scope=openid profile" --data-urlencode "state=$STATE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "username=$USER_NAME" --data-urlencode "password=$USER_PASS" \
  "$IDP/authorize")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$LOCATION")
GOT_STATE=$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$LOCATION")
check "login redirected back with a code" "yes" "$([[ -n "$CODE" ]] && echo yes || echo no)"
check "state round-tripped" "$STATE" "$GOT_STATE"

TOKENS=$(curl -s "$IDP/token" -d grant_type=authorization_code -d "client_id=$CLIENT" \
  --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER")
ACCESS=$(json_field access_token <<<"$TOKENS")
REFRESH=$(json_field refresh_token <<<"$TOKENS")
check "code exchanged for tokens" "yes" "$([[ -n "$ACCESS" && -n "$REFRESH" ]] && echo yes || echo no)"

REPLAY=$(curl -s -o /dev/null -w '%{http_code}' "$IDP/token" -d grant_type=authorization_code -d "client_id=$CLIENT" \
  --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER")
check "authorization code cannot be used twice" "400" "$REPLAY"

# Replaying the code revoked that session, so log in again for the rest.
LOCATION=$(curl -s -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "scope=openid" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "username=$USER_NAME" --data-urlencode "password=$USER_PASS" \
  "$IDP/authorize")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$LOCATION")
TOKENS=$(curl -s "$IDP/token" -d grant_type=authorization_code -d "client_id=$CLIENT" \
  --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER")
ACCESS=$(json_field access_token <<<"$TOKENS")
REFRESH=$(json_field refresh_token <<<"$TOKENS")

echo "-- 2. Calls through the proxy"
check "valid token reaches the backend" "200" "$(api hello "$ACCESS")"
check "no token is rejected" "401" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/hello")"
check "admin route for $USER_NAME" "200" "$(api admin "$ACCESS")"
IFS=. read -r H P S <<<"$ACCESS"
check "tampered signature is rejected" "401" "$(api hello "$H.$P.${S:0:20}AAAA${S:24}")"
NONE_H=$(printf '{"alg":"none","typ":"JWT"}' | b64url)
check "alg=none token is rejected" "401" "$(api hello "$NONE_H.$P.x")"

echo "-- 3. Refresh rotation and reuse detection"
NEW=$(curl -s "$IDP/token" -d grant_type=refresh_token -d "client_id=$CLIENT" --data-urlencode "refresh_token=$REFRESH")
NEW_ACCESS=$(json_field access_token <<<"$NEW")
NEW_REFRESH=$(json_field refresh_token <<<"$NEW")
check "refresh returned a new refresh token" "yes" "$([[ -n "$NEW_REFRESH" && "$NEW_REFRESH" != "$REFRESH" ]] && echo yes || echo no)"
check "old refresh token replayed -> rejected" "400" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$IDP/token" -d grant_type=refresh_token -d "client_id=$CLIENT" --data-urlencode "refresh_token=$REFRESH")"
check "current refresh token revoked with the family" "400" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$IDP/token" -d grant_type=refresh_token -d "client_id=$CLIENT" --data-urlencode "refresh_token=$NEW_REFRESH")"
echo "  waiting 4s for the proxy to pull the revocation list..."
sleep 4
check "access token from the revoked session is blocked" "401" "$(api hello "$NEW_ACCESS")"

echo
echo "== $pass passed, $fail failed"
[[ $fail -eq 0 ]]
