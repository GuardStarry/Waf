local redis = require "redis_iresty"
local template = require "resty.template"
local cjson = require "cjson" 
local cjson_decode = cjson.decode  
local ngx_log = ngx.log  
local ngx_ERR = ngx.ERR  
local ngx_exit = ngx.exit  
local ngx_print = ngx.print  
local ngx_var = ngx.var

local red = redis:new({port=1112})

local KVCount = {}
local keys, err = red:hkeys("attack:total:time")

red:init_pipeline()
for _, key in pairs(keys) do
   red:hget('attack:total:time',key)
end
local values,err = red:commit_pipeline()

for i, value in pairs(values) do
	KVCount[keys[i]] = value
end



local DayCount = {}
local keys, err = red:hkeys("counter:86400:attack")

red:init_pipeline()
for _, key in pairs(keys) do
   red:hget("counter:86400:attack", key)
end
local values,err = red:commit_pipeline()

for i, value in pairs(values) do
	DayCount[keys[i]] = value
end

local context = {KV=KVCount, Day = DayCount}
--是否缓存解析后的模板，默认true  
template.caching(true)
template.render("chart.html", context)




