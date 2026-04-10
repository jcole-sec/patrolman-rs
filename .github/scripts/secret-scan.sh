#!/usr/bin/env bash
# Secret & sensitive data scanner for CI.
# Exits non-zero when potential secrets are detected in staged/changed files.

set -euo pipefail

ALLOWLIST_FILE=".github/secret-scan-allowlist.txt"
FOUND=0

# ── Colour helpers (CI-friendly) ──────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ── Load allowlist ────────────────────────────────────────────────────────────
declare -a ALLOWED_FILES=()
declare -a ALLOWED_CONTENT=()

if [[ -f "$ALLOWLIST_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    # skip comments and blank lines
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    line="${line%%#*}"          # strip inline comments
    line="${line%"${line##*[![:space:]]}"}" # trim trailing whitespace

    if [[ "$line" == content:* ]]; then
      ALLOWED_CONTENT+=("${line#content:}")
    else
      ALLOWED_FILES+=("$line")
    fi
  done < "$ALLOWLIST_FILE"
fi

# ── Determine files to scan ──────────────────────────────────────────────────
# In a PR / push context, scan only changed files. Fallback: all tracked files.
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  FILES=$(git diff --name-only --diff-filter=ACMRT "origin/${GITHUB_BASE_REF}..HEAD" 2>/dev/null || true)
elif git rev-parse HEAD~1 >/dev/null 2>&1; then
  FILES=$(git diff --name-only --diff-filter=ACMRT HEAD~1 HEAD 2>/dev/null || true)
else
  FILES=$(git ls-files 2>/dev/null || true)
fi

if [[ -z "$FILES" ]]; then
  echo "No files to scan."
  exit 0
fi

# ── Check if a file is allowlisted ───────────────────────────────────────────
is_allowed_file() {
  local f="$1"
  for af in "${ALLOWED_FILES[@]+"${ALLOWED_FILES[@]}"}"; do
    [[ "$f" == "$af" ]] && return 0
  done
  return 1
}

# ── Check if matched text is allowlisted content ─────────────────────────────
is_allowed_content() {
  local match="$1"
  for ac in "${ALLOWED_CONTENT[@]+"${ALLOWED_CONTENT[@]}"}"; do
    [[ "$match" == *"$ac"* ]] && return 0
  done
  return 1
}

# ── Secret patterns ──────────────────────────────────────────────────────────
# Each entry: "label:::regex"
# Keep patterns broad enough to catch real leaks but narrow enough to avoid
# false positives on code/comments.
PATTERNS=(
  # Generic high-entropy API keys (hex, base64, mixed)
  "Generic API Key:::(api[_-]?key|apikey|api[_-]?secret)[[:space:]]*[=:][[:space:]]*['\"]?[A-Za-z0-9/+=_-]{16,}['\"]?"
  # AWS Access Key ID
  "AWS Access Key:::AKIA[0-9A-Z]{16}"
  # AWS Secret Access Key (40-char base64)
  "AWS Secret Key:::(aws[_-]?secret[_-]?access[_-]?key)[[:space:]]*[=:][[:space:]]*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
  # GitHub personal access tokens (classic & fine-grained)
  "GitHub Token:::gh[ps]_[A-Za-z0-9_]{36,}"
  "GitHub Fine-Grained Token:::github_pat_[A-Za-z0-9_]{22,}"
  # Generic secret / password assignment
  "Generic Secret:::(secret|password|passwd|token|credential)[[:space:]]*[=:][[:space:]]*['\"]?[A-Za-z0-9/+=_@!#$%^&*-]{8,}['\"]?"
  # Private keys (PEM)
  "Private Key:::-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
  # Connection strings with embedded credentials
  "Connection String:::(mysql|postgres|mongodb|redis|amqp|mssql)://[^ ]*:[^ ]*@"
  # Bearer tokens in code
  "Bearer Token:::Bearer [A-Za-z0-9_.=/-]{20,}"
  # Slack webhook URLs
  "Slack Webhook:::hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"
  # Generic hex tokens (32+ chars assigned to a variable)
  "Hex Token:::(token|secret|key|hash)[[:space:]]*[=:][[:space:]]*['\"]?[0-9a-fA-F]{32,}['\"]?"
)

# ── Binary/image extensions to skip ──────────────────────────────────────────
SKIP_EXT_RE='\.(png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|pdf|zip|tar|gz|exe|dll|so|dylib|bin|lock)$'

# ── Scan ─────────────────────────────────────────────────────────────────────
while IFS= read -r file; do
  [[ -z "$file" ]] && continue

  # skip binary/image files
  if echo "$file" | grep -qiE "$SKIP_EXT_RE"; then
    continue
  fi

  # skip allowlisted files
  if is_allowed_file "$file"; then
    continue
  fi

  # skip files that don't exist (deleted in diff)
  [[ -f "$file" ]] || continue

  for entry in "${PATTERNS[@]}"; do
    label="${entry%%:::*}"
    pattern="${entry##*:::}"

    matches=$(grep -nEi "$pattern" "$file" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
      while IFS= read -r match_line; do
        if ! is_allowed_content "$match_line"; then
          echo -e "${RED}[SECRET DETECTED]${NC} ${YELLOW}${label}${NC}"
          echo "  File: $file"
          echo "  $match_line"
          echo ""
          FOUND=$((FOUND + 1))
        fi
      done <<< "$matches"
    fi
  done
done <<< "$FILES"

# ── Result ───────────────────────────────────────────────────────────────────
echo "---"
if [[ "$FOUND" -gt 0 ]]; then
  echo -e "${RED}✗ Found $FOUND potential secret(s). Commit blocked.${NC}"
  echo ""
  echo "If a finding is a false positive, add it to $ALLOWLIST_FILE:"
  echo "  - Add the file path to skip the entire file"
  echo "  - Add 'content:<string>' to ignore a specific value"
  exit 1
else
  echo -e "✓ No secrets detected."
  exit 0
fi
