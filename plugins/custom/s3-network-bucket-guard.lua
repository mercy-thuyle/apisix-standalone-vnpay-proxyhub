-- plugins/custom/s3-network-bucket-guard.lua
--
-- Mục 4 kế hoạch triển khai ProxyHub: giới hạn bucket S3 theo network_id.
-- Khác hẳn cơ chế consumer_groups/consumer-restriction bên cụm S3-storage
-- (SigV4/AKID) — ở đây danh tính duy nhất là network_id lấy từ PROXY-v2 TLV
-- (đã set vào header X-Network-Id bởi global_rule "global-network-identity",
-- xem apisix_routes/global_rules/global-network-identity.yaml, mục 1).
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
            description = "Header chứa network_id, do global-network-identity set.",
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

function _M.access(conf, ctx)
    local network_id = core.request.header(ctx, conf.network_id_header)
    if not network_id or network_id == "" then
        -- Phòng thủ theo lớp — global-network-identity (mục 1) đã reject 403
        -- trước khi tới đây nếu thiếu network_id, nhánh này chỉ chạy nếu
        -- plugin bị gắn vào route/plugin_config mà global_rule đó KHÔNG áp.
        core.log.error("[", plugin_name, "] thiếu header ", conf.network_id_header,
            " — global-network-identity chưa chạy trước plugin này?")
        return conf.reject_code, { error_msg = "missing network identity" }
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

    local data, err = vault_client.get(
        conf.vault_mount, conf.vault_prefix, network_id,
        "network-bucket-allowlist", conf.cache_ttl
    )

    if err == "not_found" then
        -- network_id chưa được onboard trong Vault — LUÔN fail-closed,
        -- không phụ thuộc conf.fail_open (đó là cờ cho lỗi HẠ TẦNG Vault,
        -- không phải cho case "chính sách nói không cho phép").
        core.log.warn("[", plugin_name, "] network_id '", network_id,
            "' không có allowlist trong Vault — deny bucket '", bucket, "'")
        return conf.reject_code, { error_msg = "network not authorized for any bucket" }
    end

    if err then
        core.log.error("[", plugin_name, "] Vault lỗi hạ tầng: ", err,
            " — fail_open=", tostring(conf.fail_open))
        if conf.fail_open then
            return
        end
        return 503, { error_msg = "policy backend unavailable" }
    end

    local allowed_buckets = data.buckets
    if type(allowed_buckets) ~= "table" then
        core.log.error("[", plugin_name, "] Vault value cho network_id '", network_id,
            "' thiếu field 'buckets' dạng mảng — coi như deny toàn bộ")
        return conf.reject_code, { error_msg = "malformed policy for this network" }
    end

    for _, allowed in ipairs(allowed_buckets) do
        if allowed == bucket then
            return
        end
    end

    core.log.warn("[", plugin_name, "] network_id '", network_id,
        "' không được phép truy cập bucket '", bucket, "'")
    return conf.reject_code, { error_msg = "bucket not in allowlist for this network" }
end

return _M
