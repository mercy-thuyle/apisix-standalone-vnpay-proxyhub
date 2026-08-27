#!/usr/bin/env bash
# scripts/deploy/3-fetch-certs-vault.sh
# Fetch cert/key trực tiếp từ Vault KV v2 → plaintext ra ./certs/
# NHÁNH SONG SONG với 3-decrypt-certs.sh (không thay thế, không xoá).
# Cả 2 script cùng ghi ra ./certs/<domain>.{cert,key} — inject-certs.sh và
# APISIX standalone hot-reload phía sau dùng chung, không cần biết cert tới
# từ Vault hay từ decrypt AES. Vault fail thì quay lại chạy
# 3-decrypt-certs.sh như cũ, không phụ thuộc lẫn nhau.
#
# Dùng CERT_DOMAINS trong scripts/libraries/decrypt-cert-helper.sh (dùng
# chung với 3-decrypt-certs.sh, không tạo bản riêng).
#
# ⚠️  Khuyến nghị: đứng tại deployment dir trước khi chạy
#     cd /opt/apisix/standalone/sandbox    (hoặc production, lab, ...)
#     ./scripts/deploy/3-fetch-certs-vault.sh
#
# ⚠️  Chạy thủ công trên host khi muốn thử/dùng Vault thay vì AES:
#   1. Deploy lần đầu
#   2. Renew cert (update secret trên Vault trước, rồi chạy lại script này)
#   3. Clone repo sang host mới
#
# Sau khi fetch xong → cert sẽ được inject tự động vào apisix-${DC_PROFILE}.yaml bởi:
#   scripts/runtime/inject-certs.sh (chạy trong gitsync exechook mỗi 30s)
# APISIX standalone tự hot-reload khi file thay đổi — không cần restart container.
# Không cần chạy inject-certs.sh thủ công.
#
# Fetch qua Vault KV v2 HTTP API (curl) — cùng convention với
# plugins/libraries/vault-kv-client.lua (mount "cloud/profile", header
# X-Vault-Token). KHÔNG dùng cơ chế secret_providers/$secret://vault/...
# native của APISIX — cơ chế đó đã xác nhận có bug PEM_read_bio_X509_AUX()
# failed (vault.lua không được gọi trong ssl_phase), quyết định không dùng
# lại cho ProxyHub. Xem note-kỹ-thuật-proxyhub.md, mục Tồn đọng #6.

set -euo pipefail

DEPLOY_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "📂 Deploy dir: ${DEPLOY_DIR}"
echo ""

# ── Source cert helper (CERT_DOMAINS) — dùng chung với 3-decrypt-certs.sh ─
# shellcheck source=../libraries/decrypt-cert-helper.sh
source "${SCRIPT_DIR}/../libraries/decrypt-cert-helper.sh"
echo "🔧 CERT_DOMAINS (${#CERT_DOMAINS[@]}): ${CERT_DOMAINS[*]}"
echo ""

# ── Đọc VAULT_ADDR/VAULT_TOKEN/VAULT_MOUNT/VAULT_CERT_PREFIX từ ENV/.env ──
if [[ -f "${DEPLOY_DIR}/.env" ]]; then
  [[ -z "${VAULT_ADDR:-}" ]]        && VAULT_ADDR="$(grep -E '^VAULT_ADDR='        "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_TOKEN:-}" ]]       && VAULT_TOKEN="$(grep -E '^VAULT_TOKEN='       "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_MOUNT:-}" ]]       && VAULT_MOUNT="$(grep -E '^VAULT_MOUNT='       "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_CERT_PREFIX:-}" ]] && VAULT_CERT_PREFIX="$(grep -E '^VAULT_CERT_PREFIX=' "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
fi

VAULT_MOUNT="${VAULT_MOUNT:-cloud/profile}"
# TODO: xác nhận đúng path thật trên Vault trước khi chạy production —
# namespace phải khác app/apisix/certs (cụm S3-storage) và app/apisix-proxyhub/network-buckets (mục 4)
VAULT_CERT_PREFIX="${VAULT_CERT_PREFIX:-app/apisix-proxyhub/certs}"

if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  echo "❌ VAULT_ADDR/VAULT_TOKEN chưa được set. Export hoặc khai báo trong .env"
  exit 1
fi
echo "🔐 Vault: ${VAULT_ADDR}  (mount=${VAULT_MOUNT}, prefix=${VAULT_CERT_PREFIX})"
echo ""

# ── Paths ─────────────────────────────────────────────────────────────────
OUTPUT_CERTS="${DEPLOY_DIR}/certs"   # ← output: <domain>.cert + <domain>.key (normalized, GIỐNG 3-decrypt-certs.sh)
mkdir -p "${OUTPUT_CERTS}"

# ── Fetch từng domain từ Vault vào /dev/shm (RAM) — domain lỗi sẽ SKIP ───
TMPDIR="$(mktemp -d /dev/shm/apisix-certs-XXXXXX)"
trap 'echo "🧹 Wiping RAM tmpdir..."; rm -rf "${TMPDIR}"' EXIT
chmod 700 "${TMPDIR}"

echo "🔓 Fetching certs từ Vault KV v2 → RAM (${TMPDIR})..."
READY_DOMAINS=()
for domain in "${CERT_DOMAINS[@]}"; do
  url="${VAULT_ADDR}/v1/${VAULT_MOUNT}/data/${VAULT_CERT_PREFIX}/${domain}"
  http_code="$(curl -sk -o "${TMPDIR}/${domain}.json" -w '%{http_code}' \
    -H "X-Vault-Token: ${VAULT_TOKEN}" "${url}")"

  if [[ "${http_code}" != "200" ]]; then
    echo "   ⚠️  ${domain}  — Vault trả HTTP ${http_code} (${url}), SKIP"
    continue
  fi

  if ! python3 - "${TMPDIR}/${domain}.json" "${TMPDIR}/${domain}.cert" "${TMPDIR}/${domain}.key" <<'PYEOF'
import json, sys
resp_path, cert_path, key_path = sys.argv[1:4]
with open(resp_path) as f:
    body = json.load(f)
data = (body.get("data") or {}).get("data") or {}
cert, key = data.get("cert"), data.get("key")
if not cert or not key:
    sys.exit(1)
open(cert_path, "w").write(cert)
open(key_path, "w").write(key)
PYEOF
  then
    echo "   ⚠️  ${domain}  — thiếu field 'cert'/'key' trong secret Vault, SKIP"
    continue
  fi

  echo "   ✅ ${domain}"
  READY_DOMAINS+=("${domain}")
done

if [[ ${#READY_DOMAINS[@]} -eq 0 ]]; then
  echo ""
  echo "❌ Không có domain nào fetch được từ Vault — dùng ./scripts/deploy/3-decrypt-certs.sh (AES) thay thế"
  exit 1
fi

echo ""
# ── Validate cert ─────────────────────────────────────────────────────────
echo ""
echo "🔍 Validating certs..."
for domain in "${READY_DOMAINS[@]}"; do
  CERT_FILE="${TMPDIR}/${domain}.cert"

  openssl x509 -in "${CERT_FILE}" -noout 2>/dev/null || {
    echo "❌ Invalid cert: ${domain}"; exit 1
  }

  expiry=$(openssl x509 -in "${CERT_FILE}" -noout -enddate | cut -d= -f2)
  days_left=$(python3 -c "
from datetime import datetime, timezone
expiry = datetime.strptime('${expiry}', '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
print((expiry - datetime.now(timezone.utc)).days)")

  if [[ ${days_left} -lt 0 ]]; then
    echo "⚠️  WARNING: ${domain} EXPIRED ${days_left#-} days ago (${expiry})"
  elif [[ ${days_left} -lt 30 ]]; then
    echo "⚠️  WARNING: ${domain} expires in ${days_left} days (${expiry})"
  else
    echo "✅ Valid: ${domain} — ${days_left} days left"
  fi
done

echo ""

# ── Validate key–cert pair match ──────────────────────────────────────────
echo ""
echo "🔍 Validating key/cert pairs..."
for domain in "${READY_DOMAINS[@]}"; do
  CERT_FILE="${TMPDIR}/${domain}.cert"
  KEY_FILE="${TMPDIR}/${domain}.key"

  cert_md5=$(openssl x509 -noout -modulus -in "${CERT_FILE}" | openssl md5)
  key_md5=$(openssl rsa -noout -modulus -in "${KEY_FILE}" 2>/dev/null | openssl md5)

  if [[ "${cert_md5}" != "${key_md5}" ]]; then
    echo "❌ MISMATCH: ${domain} — cert và key không khớp" >&2
    exit 1
  fi
  echo "✅ Match: ${domain}"
done

# ── Copy ra ./certs/ — LUÔN normalize về <domain>.cert / <domain>.key ────
echo ""
echo "📁 Updating ./certs/ (normalized naming)..."
chmod 755 "${OUTPUT_CERTS}"

for domain in "${READY_DOMAINS[@]}"; do
  cp "${TMPDIR}/${domain}.cert" "${OUTPUT_CERTS}/${domain}.cert"
  cp "${TMPDIR}/${domain}.key"  "${OUTPUT_CERTS}/${domain}.key"
  chmod 640 "${OUTPUT_CERTS}/${domain}.cert"
  chmod 600 "${OUTPUT_CERTS}/${domain}.key"
  echo "✅ certs/${domain}.{cert,key}"
done

# trap EXIT tự wipe /dev/shm (kể cả JSON response thô — chứa key plaintext)

SKIPPED=$(( ${#CERT_DOMAINS[@]} - ${#READY_DOMAINS[@]} ))
echo ""
echo "✅ Done: ${#READY_DOMAINS[@]}/${#CERT_DOMAINS[@]} domains fetched từ Vault → ./certs/"
if [[ ${SKIPPED} -gt 0 ]]; then
  echo "⚠️  ${SKIPPED} domain(s) skipped — chưa có secret trong Vault tại ${VAULT_CERT_PREFIX}/<domain>"
  echo "   Domain nào skip vẫn còn cert cũ (nếu trước đó đã chạy 3-decrypt-certs.sh) — không bị mất"
fi

echo ""
echo "▶  Cert sẽ được inject tự động vào apisix.yaml khi gitsync chạy exechook (giống hệt luồng cũ)."
echo "   Để trigger ngay: git commit bất kỳ và push lên repo."
echo "   Hoặc restart gitsync: docker compose restart gitsync"
