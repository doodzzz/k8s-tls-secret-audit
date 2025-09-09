# TLS Secrets Audit for Kubernetes

A compact Bash script that scans a Kubernetes cluster for TLS secrets, **decodes base64 values**, extracts **certificate metadata**, and writes a **CSV report**. It also saves decoded `tls.crt` (and `tls.key` if present) under a structured folder.

> ⚠️ **High sensitivity**: The script can write **decoded private keys** to disk if they exist in Secrets. Use on a secure workstation only and lock down file permissions.

---

## Features

- Scans **all namespaces** by default, or a single namespace via `--namespace`  
- Accepts a custom kubeconfig via `--kubeconfig`
- Detects GNU vs BSD `date` and robustly parses OpenSSL `notAfter` formats for **days_remaining**
- CSV with key certificate fields: subject, issuer, validity window, SANs, days remaining, and key algorithm/bits (if key present)
- Saves decoded PEMs to `tls-secrets/<namespace>/<secret-name>/`

---

## Requirements

- **kubectl** (configured with access to the cluster/context you want to scan)
- **jq**
- **openssl**
- **base64** (typically present by default)
- On macOS, optional: **coreutils** for `gdate` (the script also supports BSD `date`)

```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y jq openssl

# macOS (Homebrew)
brew install jq openssl coreutils
```

---

## Installation

1. Save the script as `tls-secrets-audit.sh`.
2. Make it executable:
   ```bash
   chmod +x tls-secrets-audit.sh
   ```

> If you copied the script on Windows first, convert line endings:
> ```bash
> sed -i 's/\r$//' tls-secrets-audit.sh
> # or: dos2unix tls-secrets-audit.sh
> ```

---

## Usage

```text
Usage: ./tls-secrets-audit.sh [options]

Options:
  -n, --namespace   <name>   Only scan this namespace (default: all namespaces)
  -k, --kubeconfig  <path>   Path to kubeconfig file (default: kubectl default)
  -h, --help                 Show this help

Outputs:
  - CSV report: tls-secrets-report.csv
  - Decoded PEMs: tls-secrets/<namespace>/<secret_name>/tls.crt|tls.key
```

### Examples

- Scan **all namespaces** with current context:
  ```bash
  ./tls-secrets-audit.sh
  ```

- Scan a **single namespace**:
  ```bash
  ./tls-secrets-audit.sh -n prod
  ```

- Use a **specific kubeconfig** and namespace:
  ```bash
  ./tls-secrets-audit.sh -k ~/.kube/configs/prod -n ingress
  ```

---

## What it collects

The script selects Secrets that are:
- Type `kubernetes.io/tls`, **or**
- Have a `tls.crt` entry in `.data`

It decodes `tls.crt` (and `tls.key` if present) and extracts metadata from the certificate using OpenSSL.

### CSV Columns

`namespace, secret_name, subject, issuer, not_before, not_after, days_remaining, SANs, key_alg, key_bits`

- **subject** / **issuer**: from the certificate
- **not_before** / **not_after**: certificate validity
- **days_remaining**: days until expiry (UTC)
- **SANs**: Subject Alternative Names (comma-separated)
- **key_alg** / **key_bits**: parsed from the decoded `tls.key` when present (best-effort)

### Output Artifacts

- **Report:** `tls-secrets-report.csv`
- **Decoded files:**  
  `tls-secrets/<namespace>/<secret_name>/tls.crt`  
  `tls-secrets/<namespace>/<secret_name>/tls.key` (if present in the Secret)

---

## Security & Handling

- Treat outputs as **secret material**.
- Recommended:
  ```bash
  umask 077
  ./tls-secrets-audit.sh
  chmod -R go-rwx tls-secrets
  ```
- **Do not** commit outputs to version control. Add a `.gitignore`:
  ```gitignore
  tls-secrets/
  tls-secrets-report.csv
  ```
- Consider running on a hardened/jump workstation and removing the output directory after inspection if private keys are present.

> **Report-only mode (no private keys):**  
> Edit the script and remove the two lines that write `tls.key` and the block that inspects the key algorithm/bits.

---

## Filtering & Post-Processing

Certificates **expiring soon** (e.g., < 30 days):
```bash
awk -F',' 'NR==1 || ($7 != "" && $7 < 30)' tls-secrets-report.csv
```

Only show **expired** (days_remaining < 0):
```bash
awk -F',' 'NR==1 || ($7 != "" && $7 < 0)' tls-secrets-report.csv
```

List **unique issuers**:
```bash
cut -d',' -f4 tls-secrets-report.csv | sort -u
```

Export **a subset** of columns (namespace, secret, days_remaining):
```bash
awk -F',' 'BEGIN{OFS=","} {print $1,$2,$7}' tls-secrets-report.csv
```

---

## Troubleshooting

### `days_remaining` is blank for all rows
- You’re likely hitting a date parsing issue. The script auto-detects GNU vs BSD `date` and supports both OpenSSL date formats:
  - `"Nov 25 12:00:00 2025 GMT"`
  - `"20251125120000Z"`
- Verify OpenSSL is returning a date:
  ```bash
  openssl x509 -in tls-secrets/<ns>/<name>/tls.crt -noout -enddate
  ```
- Make sure `jq` and `openssl` are installed and in `PATH`.
- On macOS, `brew install coreutils` to get `gdate` if needed.

### `parse error near unexpected token` on running the script
- Ensure it’s saved with **Unix line endings** (LF). Convert if needed:
  ```bash
  sed -i 's/\r$//' tls-secrets-audit.sh
  ```
- Make sure it’s executable: `chmod +x tls-secrets-audit.sh`.

### No rows in CSV, but you expect some
- Confirm your kubeconfig/current context has access and the cluster actually contains TLS Secrets:
  ```bash
  kubectl get secrets -A | grep -E 'kubernetes.io/tls|tls'
  ```
- If using `--namespace`, double-check the exact namespace spelling.

---

## Limitations

- If `tls.crt` contains a **chain** (multiple certs), `openssl x509` reads only the **first** certificate for metadata.
- Key algorithm/bits detection is best-effort and depends on the private key being present in the Secret.
- The script reads **all Secrets** into a single JSON via `kubectl get secrets -A -o json`; on very large clusters this can be memory-heavy.

---

## License

MIT

---

## Acknowledgements

Created and tested by Abdullah Abdullah with AI assistance and support.
