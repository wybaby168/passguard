#!/usr/bin/env bash
set -euo pipefail

# Defensive mirror helper for the official Have I Been Pwned downloader.
# The output contains password hashes and occurrence counts, not plaintext.
# Review disk, bandwidth, backup and retention requirements before running.

OUTPUT_BASENAME="${1:-pwnedpasswords}"
HASH_MODE="${HASH_MODE:-sha1}"       # sha1 or ntlm
PARALLELISM="${PARALLELISM:-4}"
OVERWRITE="${OVERWRITE:-true}"       # true refreshes an existing corpus
MAX_RETRIES="${MAX_RETRIES:-5}"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet SDK/runtime is required: https://dotnet.microsoft.com/" >&2
  exit 1
fi

if ! command -v haveibeenpwned-downloader >/dev/null 2>&1; then
  dotnet tool install --global haveibeenpwned-downloader
  export PATH="$PATH:$HOME/.dotnet/tools"
else
  dotnet tool update --global haveibeenpwned-downloader
fi

args=("$OUTPUT_BASENAME" -p "$PARALLELISM" --max-retries "$MAX_RETRIES")
case "$OVERWRITE" in
  true|1|yes) args+=(-o) ;;
  false|0|no) ;;
  *)
    echo "OVERWRITE must be true or false" >&2
    exit 2
    ;;
esac

case "$HASH_MODE" in
  sha1)
    haveibeenpwned-downloader "${args[@]}"
    ;;
  ntlm)
    haveibeenpwned-downloader -n "${args[@]}"
    ;;
  *)
    echo "HASH_MODE must be sha1 or ntlm" >&2
    exit 2
    ;;
esac

echo "Download complete. Store the result outside public web roots and do not log lookup hashes."
