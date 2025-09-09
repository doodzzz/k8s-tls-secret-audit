#!/usr/bin/env bash
# tls-secrets-audit.sh
# Scan Kubernetes TLS secrets, decode base64, extract certificate metadata, and write a CSV.
#
# Optional params:
#   -n, --namespace   <name>   Only scan this namespace (default: all namespaces)
#   -k, --kubeconfig  <path>   Use this kubeconfig file (default: kubectl default)
#   -h, --help                 Show usage
#
# Outputs:
#   - CSV report: tls-secrets-report.csv
#   - Decoded PEMs: tls-secrets/<namespace>/<secret_name>/tls.crt|tls.key
#
# Prereqs: kubectl, jq, openssl. On macOS, 'brew install coreutils' for gdate (optional).

set -euo pipefail

NAMESPACE=""
KUBECONFIG_PATH=""
OUTDIR="tls-secrets"
CSV="tls-secrets-report.csv"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -n, --namespace   <name>   Only scan this namespace (default: all namespaces)
  -k, --kubeconfig  <path>   Path to kubeconfig file (default: kubectl default)
  -h, --help                 Show this help

Outputs:
  - CSV report: ${CSV}
  - Decoded PEMs: ${OUTDIR}/<namespace>/<secret_name>/tls.crt|tls.key
EOF
}

# --- Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)   NAMESPACE="${2:-}"; shift 2 ;;
    -k|--kubeconfig)  KUBECONFIG_PATH="${2:-}"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

# --- kubectl flags
KUBECTL_NS="-A"
if [[ -n "${NAMESPACE}" && "${NAMESPACE}" != "all" ]]; then
  KUBECTL_NS="-n ${NAMESPACE}"
fi

KUBECONFIG_OPT=()
if [[ -n "${KUBECONFIG_PATH}" ]]; then
  KUBECONFIG_OPT=(--kubeconfig "${KUBECONFIG_PATH}")
fi

mkdir -p "${OUTDIR}"
echo "namespace,secret_name,subject,issuer,not_before,not_after,days_remaining,SANs,key_alg,key_bits" > "${CSV}"

# --- Date flavor detection (GNU vs BSD)
DATE_BIN=""
DATE_FLAVOR=""  # "gnu" or "bsd"

if command -v gdate >/dev/null 2>&1; then
  DATE_BIN="gdate"; DATE_FLAVOR="gnu"
elif date --version >/dev/null 2>&1; then
  DATE_BIN="date";  DATE_FLAVOR="gnu"
else
  # macOS/BSD 'date' (no --version)
  DATE_BIN="date";  DATE_FLAVOR="bsd"
fi

# --- Helpers
to_epoch() {
  # Accepts:
  #   "Nov 25 12:00:00 2025 GMT"  OR  "20251125120000Z"
  # Also tolerates leading "notAfter=" / "notBefore=" and stray CRs
  local s="$1"
  s="${s#notAfter=}"; s="${s#notBefore=}"
  s="${s//$'\r'/}"         # strip CRs
  s="$(echo -n "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"  # trim

  if [[ "$s" =~ ^[0-9]{14}Z$ ]]; then
    # Compact Zulu format -> YYYY-MM-DD HH:MM:SS UTC
    local iso="${s:0:4}-${s:4:2}-${s:6:2} ${s:8:2}:${s:10:2}:${s:12:2} UTC"
    if [[ "$DATE_FLAVOR" == "gnu" ]]; then
      LC_ALL=C "$DATE_BIN" -u -d "$iso" +%s 2>/dev/null
    else
      LC_ALL=C "$DATE_BIN" -u -j -f '%Y-%m-%d %H:%M:%S %Z' "$iso" +%s 2>/dev/null
    fi
  else
    # e.g., "Nov 25 12:00:00 2025 GMT"
    if [[ "$DATE_FLAVOR" == "gnu" ]]; then
      LC_ALL=C "$DATE_BIN" -u -d "$s" +%s 2>/dev/null
    else
      LC_ALL=C "$DATE_BIN" -u -j -f '%b %e %T %Y %Z' "$s" +%s 2>/dev/null
    fi
  fi
}

now_epoch() {
  if [[ "$DATE_FLAVOR" == "gnu" ]]; then
    "$DATE_BIN" -u +%s
  else
    "$DATE_BIN" -u +%s
  fi
}

csv_quote() {
  # Double any internal quotes and wrap in quotes
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

# --- Main
kubectl "${KUBECONFIG_OPT[@]}" get secrets ${KUBECTL_NS} -o json \
| jq -r '
  .items[]
  | select((.type=="kubernetes.io/tls") or (.data["tls.crt"] != null))
  | [.metadata.namespace, .metadata.name, (.data["tls.crt"] // ""), (.data["tls.key"] // "")]
  | @tsv
' | while IFS=$'\t' read -r ns name crt_b64 key_b64; do
  [[ -z "$crt_b64" ]] && continue

  workdir="${OUTDIR}/${ns}/${name}"
  mkdir -p "$workdir"

  # Decode PEMs (try GNU -d first, then BSD -D)
  if ! printf '%s' "$crt_b64" | base64 -d > "$workdir/tls.crt" 2>/dev/null; then
    printf '%s' "$crt_b64" | base64 -D > "$workdir/tls.crt"
  fi
  if [[ -n "$key_b64" ]]; then
    if ! printf '%s' "$key_b64" | base64 -d > "$workdir/tls.key" 2>/dev/null; then
      printf '%s' "$key_b64" | base64 -D > "$workdir/tls.key"
    fi
  fi

  # Extract cert metadata
  subject=$(openssl x509 -in "$workdir/tls.crt" -noout -subject 2>/dev/null | sed 's/^subject= //')
  issuer=$(openssl x509 -in "$workdir/tls.crt" -noout -issuer 2>/dev/null | sed 's/^issuer= //')
  not_before=$(openssl x509 -in "$workdir/tls.crt" -noout -startdate 2>/dev/null | cut -d= -f2-)
  not_after=$(openssl x509 -in "$workdir/tls.crt" -noout -enddate 2>/dev/null | cut -d= -f2-)
  sans=$(openssl x509 -in "$workdir/tls.crt" -noout -ext subjectAltName 2>/dev/null | sed '1d' | tr -d '\n' | sed "s/^[[:space:]]*//;s/\"/'/g")

  # Days remaining
  exp_epoch=""
  if [[ -n "$not_after" ]]; then
    exp_epoch=$(to_epoch "$not_after" || true)
  fi
  now=$(now_epoch)
  days_left=""
  if [[ -n "${exp_epoch}" ]]; then
    days_left=$(( (exp_epoch - now) / 86400 ))
  fi

  # Key algorithm/bits (best-effort)
  key_alg=""
  key_bits=""
  if [[ -f "$workdir/tls.key" ]]; then
    first_line=$(openssl pkey -in "$workdir/tls.key" -text -noout 2>/dev/null | head -n1 || true)
    if echo "$first_line" | grep -q 'RSA'; then
      key_alg="RSA"
      key_bits=$(echo "$first_line" | sed -n 's/.*(\([0-9]\+\) bit).*/\1/p')
    elif echo "$first_line" | grep -qi 'EC Private-Key'; then
      curve=$(openssl pkey -in "$workdir/tls.key" -text -noout 2>/dev/null | grep 'ASN1 OID' | awk -F': ' '{print $2}')
      key_alg="EC-${curve:-unknown}"
      case "$curve" in
        prime256v1) key_bits="256" ;;
        secp384r1)  key_bits="384" ;;
        secp521r1)  key_bits="521" ;;
        *)          key_bits="$curve" ;;
      esac
    elif echo "$first_line" | grep -qi 'ED25519'; then
      key_alg="Ed25519"; key_bits="25519"
    fi
  fi

  # CSV-safe quoting for fields that may include commas
  subject_q=$(csv_quote "$subject")
  issuer_q=$(csv_quote "$issuer")
  sans_q=$(csv_quote "$sans")

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$ns" "$name" "$subject_q" "$issuer_q" "$not_before" "$not_after" "${days_left:-}" "$sans_q" "$key_alg" "$key_bits" \
    >> "${CSV}"
done

echo "✔ Wrote CSV report: ${CSV}"
echo "✔ Decoded PEMs under: ${OUTDIR}/<namespace>/<secret_name>/"

