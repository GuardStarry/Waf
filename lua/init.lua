require 'config'

local locks = require "resty.lock"
local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local switch_util = require "switch_util"
local switch_list = switch_util.switch_list
local switch_get = switch_util.get

switch_util.init(switch_list, nil)

redis = require "redis_iresty"
logpath = logdir 
rulepath = RulePath

function getClientIp()
        IP  = ngx.var.remote_addr 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if switch_get("attack.log") == "1" then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
	
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..servername.."_"..ngx.today().."_sec.log"
        log_recent(method, url, data, ruletag) 
	write(filename,line)
    end
end

function log_recent(method,url,data,ruletag)
    if switch_get("attack.log") == "1" then
	local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()

        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
	local destination = 'recent:log:attack'
	local red = redis:new({port = 1113})
	red:init_pipeline()
	red:lpush(destination, line)
	red:ltrim(destination, 0, recentLogNumber)
	red:commit_pipeline()
    end
end
    
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')
indexs=read_rule('index')
ways = read_rule('ways')

function say_html()
    if switch_get("intercept.redirect") == "1" then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if switch_get("module.white") == "1" then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
		 local resp = ngx.location.capture('/monitor', { args = { method = 'POST', url  = ngx.var.request_uri, data = '-', ruletag = "file attack with ext" .. ext } })
		say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()

        for key, val in pairs(args) do
            if type(val)=='table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
	
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
		record(rule, true)
		record("args", false)
		local resp = ngx.location.capture('/monitor',{ args = { method = 'GET', url  = ngx.var.request_uri, data = '-', ruletag = rule } })
		say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if switch_get("intercept.url") == "1" then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
		record(rule, true)
		record("url", false)
                local resp = ngx.location.capture('/monitor', { args = { method = 'GET', url  = ngx.var.request_uri, data = '-', ruletag = rule } })
		say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
		record("user-agent", false)
		local resp = ngx.location.capture('/monitor', { args = { method = 'UA', url  = ngx.var.request_uri, data = '-', ruletag = rule } })
                say_html()
            return true
            end
        end
    end
    return false
end
function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
	    record("post", false)
	    record(rule, true)
            local resp = ngx.location.capture('/monitor', { args = { method = 'POST', url  = ngx.var.request_uri, data = '-', ruletag = rule } })
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if switch_get("intercept.cookie") == "1" and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
		record(rule, true)
		record("cookie", false)
                local resp = ngx.location.capture('/monitor', { args = { method = 'COOKIE', url  = ngx.var.request_uri, data = '-', ruletag = rule } })
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if switch_get("intercept.cc") == "1" then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end
    ngx.say(header)
    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    ngx.say(m)
    if m then
        return m
    end
    
    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end

function string.split(str, delimiter)
    if str==nil or str=='' or delimiter==nil then
        return nil
    end

    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

function initStatistic()
    if switch_get("data.statistic") == "1" then
        local redW = redis:new({port=1111})
        local redR = redis:new({port=1112})
        local len, err = redR:hlen("index")
        if len == 0 then
            if indexs ~= nil then
                for _, rule in pairs(indexs) do
                    local result = string.split(rule, "`")
                    redW:hset("index", result[1], result[2])
                end
            end
        end
        local len, err = redR:hlen("attack:total:time")
        if len == 0 then
            if ways ~= nil then
                for _, rule in pairs(ways) do
                    redW:hset("attack:total:time", rule, 0)
                end
            end
        end
    end
end

function record(value, isrule)
    if isrule then
        local redR = redis:new({ port = 1112 })
        local way, err = redR:hget("index", value)
        local redW = redis:new({ port = 1111 })
        redW:hincrby("attack:total:time", way, 1)
    else
        local redW = redis:new({ port = 1111 })
        redW:hincrby("attack:total:time", value, 1)
    end
end

function update_counter()
    now = ngx.now()
    local red = redis:new({port = 1111})
    red:init_pipeline()
    for _, prec in pairs(PRECISION) do
	pnow = (math.ceil(now/prec) - 1) * prec
	hash = prec .. ':' .. 'attack'
	red:zadd('attack:counter:type', 0, hash)
	red:hincrby('counter:' .. hash, pnow, 1)
	ngx.say(pnow)
	red:commit_pipeline()
    end
end
