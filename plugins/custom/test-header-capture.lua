local core = require("apisix.core")

local plugin_name = "test-header-capture"

local schema = {
    type = "object",
    properties = {
        header_name = {
            type = "string",
            minLength = 1,
        },
    },
    required = {"header_name"},
}

local _M = {
    version = 0.1,
    priority = 1500,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    local value = core.request.header(ctx, conf.header_name)
    core.log.info("[", plugin_name, "] ",
                  conf.header_name, "=", value or "<missing>")
end

return _M
