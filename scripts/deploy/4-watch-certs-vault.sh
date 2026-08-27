#!/usr/bin/env bash
# scripts/deploy/4-watch-certs-vault.sh
# Chạy định kỳ qua cron (KHÔNG phải daemon) — check current_version trên Vault
# KV v2 (metadata, không tải nội dung cert) cho từng domain. Domain nào đổi
# version mới gọi 3-fetch-certs-vault.sh (fetch thật) + inject-certs.sh
# (ghi vào apisix-${DC_PROFILE}.yaml trực tiếp — không qua git commit, vì
# luồng Vault không đụng Git). APISIX tự thấy file đổi trong ≤1s
# (apisix/core/config_yaml.lua: ngx.timer.every(1, read_apisix_config)) và
# hot-swap trong RAM — không đóng socket, không rớt request đang chạy.
#
# Crontab gợi ý (mỗi 5 phút — đổi tuỳ nhu cầu renew cert thực tế):
#   */5 * * * * cd /opt/apisix/standalone/sandbox && ./scripts/deploy/4-watch-certs-vault.sh >> logs/vault-cert-watch.log 2>&1
#
# State lưu tại ./.vault-cert-versions/<domain>.version (host-local, gitignore).

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${DEPLOY_DIR}"

source "${DEPLOY_DIR}/scripts/libraries/decrypt-cert-helper.sh"

if [[ -f "${DEPLOY_DIR}/.env" ]]; then
  [[ -z "${VAULT_ADDR:-}" ]]        && VAULT_ADDR="$(grep -E '^VAULT_ADDR='        "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_TOKEN:-}" ]]       && VAULT_TOKEN="$(grep -E '^VAULT_TOKEN='       "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_MOUNT:-}" ]]       && VAULT_MOUNT="$(grep -E '^VAULT_MOUNT='       "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
  [[ -z "${VAULT_CERT_PREFIX:-}" ]] && VAULT_CERT_PREFIX="$(grep -E '^VAULT_CERT_PREFIX=' "${DEPLOY_DIR}/.env" | cut -d= -f2- | tr -d '[:space:]')"
fi
VAULT_MOUNT="${VAULT_MOUNT:-cloud/profile}"
VAULT_CERT_PREFIX="${VAULT_CERT_PREFIX:-app/apisix-proxyhub/certs}"

if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  echo "$(date -Is) ❌ VAULT_ADDR/VAULT_TOKEN chưa set — bỏ qua lần check này" >&2
  exit 0   # exit 0 để cron không spam mail lỗi mỗi 5 phút vì thiếu env tạm thời
fi

STATE_DIR="${DEPLOY_DIR}/.vault-cert-versions"
mkdir -p "${STATE_DIR}"

CHANGED=0
for domain in "${CERT_DOMAINS[@]}"; do
  meta_url="${VAULT_ADDR}/v1/${VAULT_MOUNT}/metadata/${VAULT_CERT_PREFIX}/${domain}"
  http_code="$(curl -sk -o "${STATE_DIR}/${domain}.meta.json" -w '%{http_code}' \
    -H "X-Vault-Token: ${VAULT_TOKEN}" "${meta_url}")"

  if [[ "${http_code}" != "200" ]]; then
    echo "$(date -Is) ⚠️  ${domain}: metadata HTTP ${http_code}, skip check lần này"
    continue
  fi

  current_version="$(python3 -c "
import json
with open('${STATE_DIR}/${domain}.meta.json') as f:
    body = json.load(f)
print((body.get('data') or {}).get('current_version', ''))
")"

  if [[ -z "${current_version}" ]]; then
    echo "$(date -Is) ⚠️  ${domain}: không đọc được current_version, skip"
    continue
  fi

  VERSION_FILE="${STATE_DIR}/${domain}.version"
  last_version="$(cat "${VERSION_FILE}" 2>/dev/null || echo '')"

  if [[ "${current_version}" != "${last_version}" ]]; then
    echo "$(date -Is) 🔔 ${domain}: version đổi ${last_version:-<none>} → ${current_version}"
    echo "${current_version}" > "${VERSION_FILE}"
    CHANGED=1
  fi
done

if [[ "${CHANGED}" -eq 0 ]]; then
  echo "$(date -Is) ✅ Không có version mới, không fetch/reload"
  exit 0
fi

echo "$(date -Is) ▶ Có version mới — fetch lại toàn bộ CERT_DOMAINS từ Vault..."
"${DEPLOY_DIR}/scripts/deploy/3-fetch-certs-vault.sh"

# KHÔNG gọi trực tiếp scripts/runtime/inject-certs.sh ở đây — file
# apisix-${DC_PROFILE}.yaml đang LIVE đã qua inject 1 lần nên KHÔNG còn
# placeholder <PASTE_CONTENT_OF_...> nữa; inject-certs.sh chỉ thay được
# placeholder, gọi lại trên file đã inject rồi sẽ skip toàn bộ domain
# (grep placeholder fail → continue) và BÁO THÀNH CÔNG GIẢ dù cert không hề
# đổi. Placeholder chỉ tồn tại lại khi merge-fragments.sh tạo STAGING mới
# từ template gốc (apisix_routes/ssls/*.yaml, git-tracked, luôn còn
# placeholder). gitsync.sh đã làm đúng chuỗi merge → inject → atomic replace
# này — gọi lại chính gitsync.sh (trong container gitsync, có lock + đúng
# path container) thay vì tự viết lại một phần.
echo "$(date -Is) ▶ Trigger lại gitsync.sh (merge fresh từ template + inject + atomic replace)..."
docker exec gitsync sh /tmp/scripts/runtime/gitsync.sh
 

echo "$(date -Is) ✅ Done — APISIX sẽ hot-swap trong ≤1s (config_yaml.lua timer), không rớt request đang chạy"
