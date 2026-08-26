-- plugins/libraries/vault-kv-client.lua
--
-- Vault KV v2 client dùng chung cho custom plugin cần lookup policy runtime
-- (khác secret_providers built-in của APISIX — cái đó chỉ resolve 1 giá trị
-- tĩnh vào field config lúc load config, KHÔNG lookup động theo key tính
-- toán lúc request như network_id ở đây).
--
-- VAULT_ADDR / VAULT_TOKEN lấy từ ENV (docker-compose đã pass sẵn, cùng biến
-- dùng cho secret_providers trong config-proxyhub.yaml) — không hardcode,
-- không đọc lại file .env.
--
-- Cache: lua_shared_dict "network-bucket-allowlist" (khai trong
-- config-proxyhub.yaml, nginx_config.http.lua_shared_dict) — mỗi worker
-- process share chung 1 vùng nhớ, KHÔNG cần Redis cho việc cache đọc này.

local core = require("apisix.core")
local http = require("resty.http")

local _M = {}

local VAULT_ADDR = os.getenv("VAULT_ADDR")
local VAULT_TOKEN = os.getenv("VAULT_TOKEN")

-- Đọc 1 key trong Vault KV v2, có cache.
--
-- @param mount    string  KV v2 mount (vd "cloud/profile")
-- @param prefix   string  path prefix trong mount (vd "app/proxyhub/network-buckets")
-- @param key      string  key cuối (vd network_id)
-- @param cache_dict_name string  tên lua_shared_dict dùng làm cache
-- @param cache_ttl number  giây — cache cả kết quả tìm thấy LẪN không tìm thấy
--                          (tránh spam Vault khi network_id lạ/không tồn tại)
-- @return table|nil data, string|nil err
--         data = nội dung field "data.data" trong response Vault KV v2
--         err  = "not_found" (204/404 — key không tồn tại, không phải lỗi hạ tầng)
--              | chuỗi mô tả lỗi hạ tầng khác (timeout, 5xx, vault down...)
function _M.get(mount, prefix, key, cache_dict_name, cache_ttl)
    local cache = ngx.shared[cache_dict_name]
    local cache_key = mount .. "/" .. prefix .. "/" .. key

    if cache then
        local cached, cached_err = cache:get(cache_key)
        if cached_err then
            core.log.warn("[vault-kv-client] lua_shared_dict '", cache_dict_name,
                "' lỗi khi get: ", cached_err, " — bỏ qua cache, gọi Vault trực tiếp")
        elseif cached == "__NOT_FOUND__" then
            return nil, "not_found"
        elseif cached then
            local ok, decoded = pcall(core.json.decode, cached)
            if ok then
                return decoded, nil
            end
            core.log.warn("[vault-kv-client] cache value hỏng cho key '", cache_key,
                "', bỏ cache — gọi lại Vault")
        end
    end

    if not VAULT_ADDR or VAULT_ADDR == "" then
        return nil, "VAULT_ADDR chưa set (env)"
    end
    if not VAULT_TOKEN or VAULT_TOKEN == "" then
        return nil, "VAULT_TOKEN chưa set (env)"
    end

    local httpc = http.new()
    httpc:set_timeout(2000)  -- 2s — không để 1 request client chờ Vault chậm/treo

    local url = VAULT_ADDR .. "/v1/" .. mount .. "/data/" .. prefix .. "/" .. key
    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = {
            ["X-Vault-Token"] = VAULT_TOKEN,
        },
        ssl_verify = false,
    })

    if not res then
        return nil, "Vault request lỗi: " .. (err or "unknown")
    end

    if res.status == 404 then
        if cache then
            cache:set(cache_key, "__NOT_FOUND__", cache_ttl)
        end
        return nil, "not_found"
    end

    if res.status ~= 200 then
        return nil, "Vault trả status " .. res.status .. ": " .. (res.body or "")
    end

    local ok, body = pcall(core.json.decode, res.body)
    if not ok or not body or not body.data or not body.data.data then
        return nil, "Vault response không đúng format KV v2 (thiếu data.data)"
    end

    local data = body.data.data

    if cache then
        local encoded = core.json.encode(data)
        cache:set(cache_key, encoded, cache_ttl)
    end

    return data, nil
end

return _M
