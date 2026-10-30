#!/usr/bin/env bash
# Generate production auth tokens in `user:token` file format.
#
# Usage:
#   scripts/generate-tokens.sh alice ci > /path/to/prod.tokens
#   scripts/generate-tokens.sh --append alice >> /path/to/prod.tokens
#
# Each token is 32 random bytes (256 bits), hex-encoded (64 chars), drawn
# from `openssl rand` when available, else /dev/urandom. Output goes to
# stdout only — this script NEVER writes to the repo, and the output file
# must NEVER be committed (see .gitignore: prod.tokens, tokens,
# *.tokens.generated). Create the k8s Secret out-of-band; see
# docs/prod-secrets.md and k8s/README.md.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: generate-tokens.sh [--append] USER [USER...]

Print `user:token` lines to stdout. One or more usernames required.
Usernames must be non-blank, contain no ':' or whitespace, and be at
most 256 chars (server limit for principals).

Examples:
  scripts/generate-tokens.sh alice ci > /tmp/prod.tokens
  scripts/generate-tokens.sh --append deploy >> /tmp/prod.tokens
EOF
}

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -v -An -tx1 -N32 /dev/urandom | tr -d ' \n'
    printf '\n'
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "${1:-}" = "--append" ]; then
  shift
fi

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

for user in "$@"; do
  case "$user" in
    *:*|*[!A-Za-z0-9_.-]*|"" )
      echo "generate-tokens.sh: invalid username '$user' (use [A-Za-z0-9_.-], no ':')" >&2
      exit 1
      ;;
  esac
  if [ "${#user}" -gt 256 ]; then
    echo "generate-tokens.sh: username '$user' exceeds 256 chars" >&2
    exit 1
  fi
  printf '%s:%s\n' "$user" "$(rand_hex)"
done
