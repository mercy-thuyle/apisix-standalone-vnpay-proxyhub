-- plugins/custom/s3-network-bucket-guard.lua
--
-- Mục 4 kế hoạch triển khai ProxyHub: giới hạn bucket S3 theo network_id.
-- Khác hẳn cơ chế consumer_groups/consumer-restriction bên cụm S3-storage
-- (SigV4/AKID) — ở đây danh tính chính là network_id lấy từ PROXY-v2 TLV
-- (đã set vào header X-Network-Id bởi global_rule "global-network-identity",
-- xem apisix_routes/global_rules/global-network-identity.yaml, mục 1).
--
-- Đổi chính sách 23/09/2026: network_id là identity tùy chọn. Khi request có
-- X-Network-Id, plugin tra Vault và enforce bucket allowlist. Khi không có
-- header này, plugin không áp bucket allowlist và cho request đi tiếp để tầng
-- S3-storage/Cloudian xử lý xác thực SigV4 cùng quyền bucket/object.
--
-- Bổ sung 25/09/2026: default_allowlist_key (tùy chọn) — allowlist mặc định trên Vault
-- áp cho request KHÔNG có X-Network-Id hoặc có nhưng network_id chưa onboard trên
-- Vault. Thứ tự tra: allowlist riêng của network_id (nếu có) → allowlist mặc định.
-- Không khai default_allowlist_key → giữ hành vi cũ (thiếu network_id thì bỏ qua).
--
-- Bổ sung 25/09/2026: phần tử allowlist kết thúc bằng "*" khớp theo prefix
-- (vd "proxy-hub-hcm-*" cho bucket client tự tạo dạng proxy-hub-hcm-<id ngẫu nhiên>).
-- Áp cho cả allowlist mặc định lẫn allowlist theo network_id. Xem bucket_in().
--
-- Allowlist KHÔNG nằm trong GitOps YAML (route/plugin_config) — nằm trong
-- Vault KV v2, để team quản lý network onboard/thu hồi tenant KHÔNG cần
-- đụng vào route/service/GitOps của Gateway team. Plugin này chỉ đọc
-- (read-only) Vault tại request-time, có cache để không gọi Vault mỗi
-- request (xem plugins/libraries/vault-kv-client.lua).

local core = require("apisix.core")
local vault_client = require("vault-kv-client")

local plugin_name = "s3-network-bucket-guard"

local schema = {
    type = "object",
    properties = {
        network_id_header = {
            type = "string",
            description = "Header chứa network_id, do global-network-identity set. "
                        .. "Không bắt buộc: thiếu header thì bỏ qua bucket allowlist.",
            default = "X-Network-Id",
        },
        apex_host = {
            type = "string",
            description = "Domain gốc dùng để phân biệt virtual-hosted-style "
                        .. "(bucket.<apex_host>) và path-style (<apex_host>/bucket/...). "
                        .. "Bắt buộc khai đúng khớp domain thật trong route hosts.",
        },
        vault_mount = {
            type = "string",
            description = "KV v2 mount chứa allowlist — KHÁC mount cert "
                        .. "(secret_providers.vault-provider dùng mount riêng cho cert).",
            default = "cloud/profile",
        },
        vault_prefix = {
            type = "string",
            description = "Path prefix trong mount, key cuối = network_id. "
                        .. "Vault path đầy đủ: <vault_mount>/data/<vault_prefix>/<network_id>. "
                        .. "Value kỳ vọng field 'buckets': mảng string. "
                        .. "Namespace riêng app/apisix-proxyhub/* (tách khỏi app/apisix/* "
                        .. "của cụm S3-storage) — xác nhận quyền 'read' qua "
                        .. "sys/capabilities-self, token re-login sau khi Vault team cấp "
                        .. "policy mới (token cũ không tự nhận policy mới cho tới khi "
                        .. "login lại).",
            default = "app/apisix-proxyhub/network-buckets",
        },
        cache_ttl = {
            type = "integer",
            description = "Giây — cache allowlist mỗi network_id (cache CẢ "
                        .. "kết quả không tìm thấy, tránh spam Vault với "
                        .. "network_id lạ). Đổi allowlist trên Vault có thể "
                        .. "mất tới cache_ttl giây mới apply — không phải "
                        .. "real-time tuyệt đối, đánh đổi lấy giảm tải Vault.",
            default = 60,
            minimum = 5,
        },
        fail_open = {
            type = "boolean",
            description = "Khi Vault KHÔNG truy cập được (network/5xx/timeout, "
                        .. "KHÁC với network_id không có trong Vault — case đó "
                        .. "luôn fail-closed bất kể cờ này): true = cho request "
                        .. "đi tiếp (ưu tiên uptime S3, chấp nhận rủi ro bucket "
                        .. "không đúng allowlist lọt qua trong lúc Vault down); "
                        .. "false = chặn (ưu tiên đúng chính sách, chấp nhận "
                        .. "S3 downtime nếu Vault down). Mặc định false — "
                        .. "đổi có chủ đích, không phải default an toàn chung chung.",
            default = false,
        },
        reject_code = {
            type = "integer",
            default = 403,
        },
        default_allowlist_key = {
            type = "string",
            minLength = 1,
            description = "Key Vault (cùng vault_mount/vault_prefix) chứa allowlist mặc định "
                        .. "cho request không có network_id hoặc network_id chưa có trên Vault. "
                        .. "Tách theo site (vd _default-hcm/_default-hni) để mỗi endpoint chỉ "
                        .. "cho bucket của site đó. Không khai = giữ hành vi cũ: thiếu "
                        .. "network_id thì bỏ qua allowlist. Đã khai mà key không tồn tại "
                        .. "trên Vault → deny mọi request nhắm bucket (fail-closed).",
        },
    },
    required = {"apex_host"},
}

local _M = {
    version  = 0.1,
    priority = 2000,
    name     = plugin_name,
    schema   = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Tách bucket name từ request, theo đúng 2 kiểu route hosts đang khai
-- (apex + wildcard subdomain) trong apisix_routes/routes/s3/route-s3.yaml.
-- Trả về "" (chuỗi rỗng, KHÔNG phải nil) khi request không nhắm 1 bucket cụ
-- thể (vd ListBuckets ở apex path "/") — đây là request account-level, guard
-- này chủ đích KHÔNG chặn (ủy quyền lại cho tầng S3-storage/Cloudian phía
-- sau xử lý theo AKID của chính request đó).
local function extract_bucket(ctx, apex_host)
    local host = ctx.var.host or ""

    if host == apex_host then
        -- path-style: /<bucket>/<key...>
        local uri = ctx.var.uri or "/"
        local bucket = uri:match("^/([^/]+)")
        return bucket or ""
    end

    local suffix = "." .. apex_host
    if host:sub(-#suffix) == suffix then
        -- virtual-hosted-style: <bucket>.<apex_host>
        return host:sub(1, #host - #suffix)
    end

    -- Host không khớp apex lẫn wildcard — không nên xảy ra vì route đã lọc
    -- theo hosts, nhưng vẫn xử lý an toàn thay vì crash.
    return nil
end

-- Tra allowlist của 1 key trên Vault. Trả về:
--   buckets(table), nil        → có allowlist hợp lệ
--   nil, "not_found"           → key chưa có trên Vault
--   nil, "malformed"           → có key nhưng thiếu field 'buckets' dạng mảng
--   nil, <lỗi hạ tầng>         → Vault không truy cập được
local function fetch_allowlist(conf, key)
    local data, err = vault_client.get(
        conf.vault_mount, conf.vault_prefix, key,
        "network-bucket-allowlist", conf.cache_ttl
    )
    if err then
        return nil, err
    end
    if type(data.buckets) ~= "table" then
        return nil, "malformed"
    end
    return data.buckets, nil
end

-- So khớp bucket với allowlist. Mỗi phần tử:
--   "proxy-hub-hcm"    → khớp CHÍNH XÁC tên bucket.
--   "proxy-hub-hcm-*"  → khớp theo PREFIX (dấu "*" chỉ có nghĩa khi đứng CUỐI):
--                        mọi bucket bắt đầu bằng "proxy-hub-hcm-" (bucket client tự tạo
--                        với hậu tố ngẫu nhiên).
-- So sánh chuỗi thuần (string.sub), KHÔNG dùng Lua pattern — tên bucket chứa "-" và "."
-- là ký tự đặc biệt của pattern, dùng pattern sẽ khớp sai.
-- "*" đứng một mình (prefix rỗng) bị BỎ QUA, không hiểu là "cho phép mọi bucket" —
-- tránh 1 lỗi gõ trên Vault vô hiệu hoá toàn bộ allowlist.
local function bucket_in(list, bucket)
    for _, allowed in ipairs(list) do
        if type(allowed) == "string" and allowed ~= "" then
            if allowed:sub(-1) == "*" then
                local prefix = allowed:sub(1, -2)
                if prefix ~= "" and bucket:sub(1, #prefix) == prefix then
                    return true
                end
            elseif allowed == bucket then
                return true
            end
        end
    end
    return false
end

function _M.access(conf, ctx)
    local network_id = core.request.header(ctx, conf.network_id_header)
    if network_id == "" then
        network_id = nil
    end

    -- Không network_id và không khai allowlist mặc định → hành vi cũ: bỏ qua.
    if not network_id and not conf.default_allowlist_key then
            core.log.info("[", plugin_name, "] thiếu header ", conf.network_id_header,
            " và không khai default_allowlist_key — bỏ qua bucket allowlist")
        return
    end

    local bucket = extract_bucket(ctx, conf.apex_host)
    if bucket == nil then
        core.log.error("[", plugin_name, "] Host '", ctx.var.host,
            "' không khớp apex_host '", conf.apex_host, "' lẫn dạng wildcard của nó")
        return conf.reject_code, { error_msg = "unrecognized host" }
    end

    if bucket == "" then
        -- Request account-level (không nhắm bucket cụ thể) — không thuộc
        -- phạm vi guard này, cho đi tiếp.
        return
    end

    local allowed_buckets, source, err

    -- Bước 1: allowlist riêng của network_id (nếu request có network_id).
    if network_id then
        allowed_buckets, err = fetch_allowlist(conf, network_id)
        source = "network_id '" .. network_id .. "'"

        if err == "not_found" then
            if not conf.default_allowlist_key then
                -- Hành vi cũ: network_id chưa onboard → LUÔN fail-closed.
                core.log.warn("[", plugin_name, "] network_id '", network_id,
                    "' không có allowlist trong Vault — deny bucket '", bucket, "'")
                return conf.reject_code, { error_msg = "network not authorized for any bucket" }
            end
            core.log.info("[", plugin_name, "] network_id '", network_id,
                "' chưa có allowlist riêng — dùng allowlist mặc định '",
                conf.default_allowlist_key, "'")
            allowed_buckets, err = nil, nil
        end
    end

    -- Bước 2: allowlist mặc định (không có network_id, hoặc network_id chưa onboard).
    if not allowed_buckets and not err then
        allowed_buckets, err = fetch_allowlist(conf, conf.default_allowlist_key)
        source = "default '" .. conf.default_allowlist_key .. "'"

        if err == "not_found" then
            core.log.error("[", plugin_name, "] default_allowlist_key '",
                conf.default_allowlist_key, "' không tồn tại trên Vault — deny bucket '",
                bucket, "'")
            return conf.reject_code, { error_msg = "bucket allowlist not configured" }
        end
    end

    if err == "malformed" then
        core.log.error("[", plugin_name, "] Vault value cho ", source,
            " thiếu field 'buckets' dạng mảng — coi như deny toàn bộ")
        return conf.reject_code, { error_msg = "malformed bucket allowlist" }
    end

    if err then
        core.log.error("[", plugin_name, "] Vault lỗi hạ tầng (", source, "): ", err,
            " — fail_open=", tostring(conf.fail_open))
        if conf.fail_open then
            return
        end
        return 503, { error_msg = "policy backend unavailable" }
    end

    if bucket_in(allowed_buckets, bucket) then
        return
    end

    core.log.warn("[", plugin_name, "] bucket '", bucket, "' không có trong allowlist của ",
        source)
    return conf.reject_code, { error_msg = "bucket not in allowlist" }
end

return _M
