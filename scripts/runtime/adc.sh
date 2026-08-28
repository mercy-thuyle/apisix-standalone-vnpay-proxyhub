#!/bin/sh
set -eu
SYNC_SRC=/tmp/sync/current; ADC_DIR=/tmp/adc; PROFILE="${DC_PROFILE:?DC_PROFILE is required}"
REQUEST="${ADC_DIR}/request-${PROFILE}"; RESULT="${ADC_DIR}/result-${PROFILE}"
mkdir -p "${ADC_DIR}/work"; last_commit=""
result() { tmp="${RESULT}.tmp.$$"; printf '%s\t%s\t%s\n' "$1" "$2" "$3" > "$tmp"; mv "$tmp" "$RESULT"; }
validate() {
  commit="$1"; work="${ADC_DIR}/work/${PROFILE}-${commit}"; rm -rf "$work"; mkdir -p "$work"
  actual="$(git -C "$SYNC_SRC" rev-parse HEAD 2>/dev/null || true)"
  [ "$actual" = "$commit" ] || { result "$commit" FAIL "checkout changed during validation"; return; }
  if ! SKIP_SAMPLE_UPDATE=1 DC_PROFILE="$PROFILE" sh "$SYNC_SRC/scripts/runtime/merge-fragments.sh" "$SYNC_SRC/apisix_routes" "$work/apisix-${PROFILE}.yaml" >"$work/merge.log" 2>&1; then result "$commit" FAIL "merge failed"; return; fi
  cp "$SYNC_SRC/apisix_config/config-${PROFILE}.yaml" "/usr/local/apisix/conf/config-${PROFILE}.yaml"
  cp "$work/apisix-${PROFILE}.yaml" "/usr/local/apisix/conf/apisix-${PROFILE}.yaml"
  rm -rf /usr/local/apisix/apisix/plugins/custom /usr/local/apisix/apisix/plugins/libraries
  ln -s "$SYNC_SRC/plugins/custom" /usr/local/apisix/apisix/plugins/custom
  ln -s "$SYNC_SRC/plugins/libraries" /usr/local/apisix/apisix/plugins/libraries
  for patch in vault config_yaml kafka-logger; do
    [ -f "/tmp/adc-patches/${patch}.lua" ] || continue
    case "$patch" in vault) target=/usr/local/apisix/apisix/secret/vault.lua;; config_yaml) target=/usr/local/apisix/apisix/core/config_yaml.lua;; kafka-logger) target=/usr/local/apisix/apisix/plugins/kafka-logger.lua;; esac
    cp "/tmp/adc-patches/${patch}.lua" "$target"
  done
  if ! find "$SYNC_SRC/plugins" -type f -name '*.lua' -print0 | sort -z | xargs -0 -r -n1 /usr/local/openresty/luajit/bin/luajit -bl >/dev/null; then result "$commit" FAIL "Lua syntax failed"; return; fi
  if ! apisix init >"$work/apisix-init.log" 2>&1; then result "$commit" FAIL "apisix init failed"; return; fi
  # Boot ngắn trong network none để config_yaml nạp entity/plugin schema.
  if ! apisix start >"$work/apisix-start.log" 2>&1; then result "$commit" FAIL "apisix start failed"; return; fi
  ready=0; for _ in $(seq 1 20); do apisix status >/dev/null 2>&1 && { ready=1; break; }; sleep 0.25; done
  apisix quit >/dev/null 2>&1 || true
  [ "$ready" -eq 1 ] || { result "$commit" FAIL "APISIX worker not ready"; return; }
  cp "$work/apisix-${PROFILE}.yaml" "${ADC_DIR}/approved-${PROFILE}.yaml"
  result "$commit" PASS validated
}
while :; do
  if [ -s "$REQUEST" ]; then commit="$(cat "$REQUEST" 2>/dev/null || true)"; if [ -n "$commit" ] && [ "$commit" != "$last_commit" ]; then last_commit="$commit"; validate "$commit"; fi; fi
  sleep 1
done
