local local_switch_cache = ngx.shared.local_switch_cache

local switch_list = {
	{
		des = "whether to open attack log",
		key = "attack.log",
		value = "1"
	},
	{
		des = "whether to open data statistic",
		key = "data.statistic",
		value = "1"
	},
	{
		des = "whether to open url interception",
		key = "intercept.url",
		value = "1"
	},
	{
		des = "whether to open redirect interception",
		key = "intercept.redirect",
		value = "1"
	},
	{
		des = "whether to open cookie interception",
		key = "intercept.cookie",
		value = "1"
	},
	{
		des = "whether to open post interception",
		key = "intercept.post",
		value = "1"
	},
	{
		des = "whether to open white module",
		key = "module.white",
		value = "1"
	},
	{
		des = "whether to open cc interception",
		key = "intercept.cc",
		value = "1"
	}
}


local function init(config, forceInit)
    if not local_switch_cache then
        return
    end

    if local_switch_cache:get("inited") == "1" and not forceInit then
        ngx.log(ngx.ERR, "nginx switch has inited")
        return
    end

    for _, c in ipairs(config) do
        local_switch_cache:set(c.key, c.value)
    end
    local_switch_cache:set("inited", "1")
end

local function set(key, value)
    if not local_switch_cache then
        return
    end
    local_switch_cache:set(key, value)
end

local function get(key)
    if not local_switch_cache then
        return nil
    end
    return local_switch_cache:get(key)
end


local function list(config)
    if not local_switch_cache then
        return
    end

    local result = {}

    for _, c in ipairs(config) do
        result[#result + 1] = {
            desc  = c.desc,
            key   = c.key,
            value = local_switch_cache:get(c.key)
        }
    end

    return result
end

local function eq(key, value)
    if not local_switch_cache then
        return nil
    end
    return get(key) == value
end


local _M = {
    switch_list = switch_list,
    init = init,
    set = set,
    get = get,
    list = list,
    eq = eq
}

return _M
