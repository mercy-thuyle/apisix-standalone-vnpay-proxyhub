#!/bin/sh

# VNPAY ADC (bộ điều khiển dry-run APISIX)
#
# GitSync ghi SHA của commit vào /tmp/adc/request-<profile>. Container chạy nền
# này kiểm tra đúng checkout đó trong môi trường không có network, sau đó ghi
# một dòng kết quả theo cách atomic vào /tmp/adc/result-<profile>:
#   <commit>\tPASS|FAIL\t<detail>
#
# PASS đồng thời tạo approved-<profile>.yaml, chứng minh candidate đã merge và
# được APISIX chấp nhận. Chỉ GitSync mới được promote file staging đã inject
# của chính nó sang file route live đang bind mount.

set -eu

# ── Trạng thái dùng chung và checkout source ─────────────────────────────────
SYNC_SRC="/tmp/sync/current"
ADC_DIR="/tmp/adc"
PROFILE="${DC_PROFILE:?DC_PROFILE is required}"

REQUEST="${ADC_DIR}/request-${PROFILE}"
RESULT="${ADC_DIR}/result-${PROFILE}"
HEARTBEAT="${ADC_DIR}/heartbeat-${PROFILE}"
LOG_DIR="/tmp/logs/adc"
LOG_FILE="${LOG_DIR}/adc.log"

mkdir -p "${ADC_DIR}/work"
mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}" 2>/dev/null || true
last_commit=""

# Ghi log vận hành ra Docker stdout và logs/adc/adc.log trên host.
# Không log nội dung YAML hoặc biến môi trường để tránh lộ secret.
log() {
  _msg="[adc] $(date -Iseconds) $*"
  printf '%s\n' "${_msg}"
  printf '%s\n' "${_msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

# Ghi verdict theo cách atomic để GitSync không đọc phải dòng dang dở.
result() {
  commit="$1"
  status="$2"
  detail="$3"
  tmp="${RESULT}.tmp.$$"

  printf '%s\t%s\t%s\n' "${commit}" "${status}" "${detail}" > "${tmp}"
  mv "${tmp}" "${RESULT}"
  log "VERDICT — commit=${commit} status=${status} detail=${detail}"
}

# Validate một checkout GitSync bất biến. Mọi lỗi đều trả về cho bên yêu cầu;
# controller vẫn tiếp tục chạy để xử lý commit kế tiếp.
validate() {
  commit="$1"
  work="${ADC_DIR}/work/${PROFILE}-${commit}"
  # File chứng thực mang SHA để GitSync chỉ chấp nhận đúng transaction này.
  approved="${ADC_DIR}/approved-${PROFILE}-${commit}.yaml"

  rm -rf "${work}"
  mkdir -p "${work}"
  log "START — commit=${commit} work=${work}"

# GitSync chỉ gọi exechook sau khi checkout hoàn tất và chờ hook kết thúc trước khi sync tiếp.
# Lock của gitsync.sh cũng chặn transaction chồng nhau;
# vì vậy commit trong request chính là revision bất biến của lần validate này.
#   # Không validate request cũ nếu GitSync đã chuyển sang checkout mới hơn.
#   actual="$(git -C "${SYNC_SRC}" rev-parse HEAD 2>/dev/null || true)"
#   if [ "${actual}" != "${commit}" ]; then
#     result "${commit}" FAIL "checkout changed during validation"
#     return
#   fi

  # Chỉ merge từ source đã pull. samples/runtime tuyệt đối không bị ghi đè.
  if ! SKIP_SAMPLE_UPDATE=1 \
       DC_PROFILE="${PROFILE}" \
       sh "${SYNC_SRC}/scripts/runtime/merge-fragments.sh" \
       "${SYNC_SRC}/apisix_routes" \
       "${work}/apisix-${PROFILE}.yaml" > "${work}/merge.log" 2>&1; then
    result "${commit}" FAIL "merge failed"
    return
  fi
  log "OK — merge fragments"

  # Dựng private view APISIX của validator từ checkout candidate.
  cp "${SYNC_SRC}/apisix_config/config-${PROFILE}.yaml" \
     "/usr/local/apisix/conf/config-${PROFILE}.yaml"
  cp "${work}/apisix-${PROFILE}.yaml" \
     "/usr/local/apisix/conf/apisix-${PROFILE}.yaml"

  # Chỉ thay file bên trong ADC container dùng một lần, không đụng file host.
  rm -rf /usr/local/apisix/apisix/plugins/custom \
         /usr/local/apisix/apisix/plugins/libraries
  ln -s "${SYNC_SRC}/plugins/custom" \
        /usr/local/apisix/apisix/plugins/custom
  ln -s "${SYNC_SRC}/plugins/libraries" \
        /usr/local/apisix/apisix/plugins/libraries

  # Giữ validator đồng nhất với các file override của image APISIX production.
  for patch in vault config_yaml kafka-logger; do
    [ -f "/tmp/adc-patches/${patch}.lua" ] || continue

    case "${patch}" in
      vault)
        target="/usr/local/apisix/apisix/secret/vault.lua"
        ;;
      config_yaml)
        target="/usr/local/apisix/apisix/core/config_yaml.lua"
        ;;
      kafka-logger)
        target="/usr/local/apisix/apisix/plugins/kafka-logger.lua"
        ;;
    esac

    cp "/tmp/adc-patches/${patch}.lua" "${target}"
  done

  # Compile mọi Lua plugin trong repo trước khi APISIX nạp schema của chúng.
  if ! find "${SYNC_SRC}/plugins" -type f -name '*.lua' -print0 \
       | sort -z \
       | xargs -0 -r -n1 /usr/local/openresty/luajit/bin/luajit -bl \
         > /dev/null; then
    result "${commit}" FAIL "Lua syntax failed"
    return
  fi
  log "OK — Lua syntax"

  if ! apisix init > "${work}/apisix-init.log" 2>&1; then
    result "${commit}" FAIL "apisix init failed"
    return
  fi
  log "OK — apisix init"

  # Boot ngắn trong network none: config_yaml nạp entity và plugin schema.
  if ! apisix start > "${work}/apisix-start.log" 2>&1; then
    log "FAIL — apisix start; xem ${work}/apisix-start.log"
    result "${commit}" FAIL "apisix start failed"
    return
  fi
  log "OK — apisix start"

  ready=0
  for _ in $(seq 1 20); do
    if apisix status > /dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.25
  done

  # Dừng worker chạy ngắn ở cả trường hợp thành công và không ready.
  apisix quit > /dev/null 2>&1 || true

  if [ "${ready}" -ne 1 ]; then
    result "${commit}" FAIL "APISIX worker not ready"
    return
  fi

  # Artifact này chứng minh ADC thành công; GitSync giữ staging đã inject cert.
  cp "${work}/apisix-${PROFILE}.yaml" "${approved}"
  result "${commit}" PASS "validated"
}

# ── Vòng lặp điều khiển ─────────────────────────────────────────────────────
# Không validate lại cùng request mỗi giây. SHA mới tạo một transaction validate
# mới.
while :; do
  # Healthcheck dùng timestamp này để phát hiện controller bị treo.
  date +%s > "${HEARTBEAT}"

  if [ -s "${REQUEST}" ]; then
    commit="$(cat "${REQUEST}" 2>/dev/null || true)"

    if [ -n "${commit}" ] && [ "${commit}" != "${last_commit}" ]; then
      last_commit="${commit}"
      validate "${commit}"
    fi
  fi

  sleep 1
done
