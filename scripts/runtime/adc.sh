#!/bin/sh

# VNPAY ADC (APISIX dry-run controller)
#
# GitSync writes a commit SHA to /tmp/adc/request-<profile>.  This long-running
# container validates that exact checkout without network access, then writes
# one atomic verdict line to /tmp/adc/result-<profile>:
#   <commit>\tPASS|FAIL\t<detail>
#
# A PASS also creates approved-<profile>.yaml as proof that the candidate was
# merged and accepted by APISIX.  GitSync is the only component that promotes
# its own injected staging file to the live bind-mounted route file.

set -eu

# ── Shared state and source checkout ────────────────────────────────────────
SYNC_SRC="/tmp/sync/current"
ADC_DIR="/tmp/adc"
PROFILE="${DC_PROFILE:?DC_PROFILE is required}"

REQUEST="${ADC_DIR}/request-${PROFILE}"
RESULT="${ADC_DIR}/result-${PROFILE}"
APPROVED="${ADC_DIR}/approved-${PROFILE}.yaml"

mkdir -p "${ADC_DIR}/work"
last_commit=""

# Write verdict atomically so GitSync cannot consume a partly-written line.
result() {
  commit="$1"
  status="$2"
  detail="$3"
  tmp="${RESULT}.tmp.$$"

  printf '%s\t%s\t%s\n' "${commit}" "${status}" "${detail}" > "${tmp}"
  mv "${tmp}" "${RESULT}"
}

# Validate one immutable GitSync checkout.  Every failure is reported to the
# requestor and returns normally so the controller can serve the next commit.
validate() {
  commit="$1"
  work="${ADC_DIR}/work/${PROFILE}-${commit}"

  rm -rf "${work}"
  mkdir -p "${work}"

  # Never validate an outdated request after GitSync has advanced its checkout.
  actual="$(git -C "${SYNC_SRC}" rev-parse HEAD 2>/dev/null || true)"
  if [ "${actual}" != "${commit}" ]; then
    result "${commit}" FAIL "checkout changed during validation"
    return
  fi

  # Merge from the pulled source only.  samples/runtime must stay untouched.
  if ! SKIP_SAMPLE_UPDATE=1 \
       DC_PROFILE="${PROFILE}" \
       sh "${SYNC_SRC}/scripts/runtime/merge-fragments.sh" \
       "${SYNC_SRC}/apisix_routes" \
       "${work}/apisix-${PROFILE}.yaml" > "${work}/merge.log" 2>&1; then
    result "${commit}" FAIL "merge failed"
    return
  fi

  # Build the validator's private APISIX view from the candidate checkout.
  cp "${SYNC_SRC}/apisix_config/config-${PROFILE}.yaml" \
     "/usr/local/apisix/conf/config-${PROFILE}.yaml"
  cp "${work}/apisix-${PROFILE}.yaml" \
     "/usr/local/apisix/conf/apisix-${PROFILE}.yaml"

  # Replace only files inside this disposable ADC container, never host files.
  rm -rf /usr/local/apisix/apisix/plugins/custom \
         /usr/local/apisix/apisix/plugins/libraries
  ln -s "${SYNC_SRC}/plugins/custom" \
        /usr/local/apisix/apisix/plugins/custom
  ln -s "${SYNC_SRC}/plugins/libraries" \
        /usr/local/apisix/apisix/plugins/libraries

  # Keep the validator aligned with the production APISIX image overrides.
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

  # Compile every repo Lua plugin before APISIX attempts to load its schema.
  if ! find "${SYNC_SRC}/plugins" -type f -name '*.lua' -print0 \
       | sort -z \
       | xargs -0 -r -n1 /usr/local/openresty/luajit/bin/luajit -bl \
         > /dev/null; then
    result "${commit}" FAIL "Lua syntax failed"
    return
  fi

  if ! apisix init > "${work}/apisix-init.log" 2>&1; then
    result "${commit}" FAIL "apisix init failed"
    return
  fi

  # Short, network-isolated boot: config_yaml loads entities and plugin schema.
  if ! apisix start > "${work}/apisix-start.log" 2>&1; then
    result "${commit}" FAIL "apisix start failed"
    return
  fi

  ready=0
  for _ in $(seq 1 20); do
    if apisix status > /dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.25
  done

  # Stop the short-lived worker on both success and readiness failure.
  apisix quit > /dev/null 2>&1 || true

  if [ "${ready}" -ne 1 ]; then
    result "${commit}" FAIL "APISIX worker not ready"
    return
  fi

  # This artifact is proof of ADC success; GitSync retains cert-injected staging.
  cp "${work}/apisix-${PROFILE}.yaml" "${APPROVED}"
  result "${commit}" PASS "validated"
}

# ── Controller loop ─────────────────────────────────────────────────────────
# Re-reading the same request must not revalidate it every second.  A new SHA
# becomes a new validation transaction.
while :; do
  if [ -s "${REQUEST}" ]; then
    commit="$(cat "${REQUEST}" 2>/dev/null || true)"

    if [ -n "${commit}" ] && [ "${commit}" != "${last_commit}" ]; then
      last_commit="${commit}"
      validate "${commit}"
    fi
  fi

  sleep 1
done
