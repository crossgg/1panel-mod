-- 1pwaf「城市级地区限制」补丁（包装官方模块，不改原有行为）
--
-- 部署方式（不需要重新构建容器/镜像）：
--   1. 把本文件放到宿主机挂载卷 <openresty>/1pwaf/data/lua/location_restrict.lua
--   2. 在 <openresty>/1pwaf/data/conf/waf.conf 的 lua_package_path 最前面加
--      /usr/local/openresty/1pwaf/data/lua/?.lua;
--   3. nginx -t && nginx -s reload
-- 因为两个文件都在挂载卷里，容器重建也不会丢；1Panel 应用升级若重写 waf.conf，
-- 重新执行安装脚本 / 设置页「应用 Lua 补丁」即可。
--
-- 原理：官方 location_restrict.lua 是 LuaJIT 字节码。这里用 dofile 加载原模块，
-- 保留它的 evaluate 全部行为（国家 iso / 省份 province.en / schemaVersion / LOCAL /
-- 港澳台特例），只在它判定为「不拦截」之后追加一次 cityRules 判定。
-- 这样国家与省份限制 100% 不受影响。
--
-- 城市来源：geoip.lookup() 丢掉了 mmdb 的 city 字段，所以这里直接用
-- ngx.ctx.ip（WAF 已算好的真实客户端 IP，含 CDN 修正）再查一次 mmdb 原始记录。
-- 若 GeoIP.mmdb 不含 city（镜像自带的国家/省份库就没有），cityOf() 返回空串，
-- 此时不做任何城市拦截，绝不会误伤。

local ORIGINAL = "/usr/local/openresty/1pwaf/lib/location_restrict.lua"
local ok, original = pcall(dofile, ORIGINAL)
if not ok or type(original) ~= "table" or type(original.evaluate) ~= "function" then
    -- 加载失败时保持安全：完全交还给默认行为（不拦截），不阻断业务
    return { evaluate = function() return false end }
end

local mmdb = require "resty.maxminddb"

local function inList(list, value)
    if type(list) ~= "table" or not value or value == "" then
        return false
    end
    for _, v in ipairs(list) do
        if v == value then
            return true
        end
    end
    return false
end

-- allow = 名单外一律拦；deny = 命中名单才拦
local function blocked(action, hit)
    if action == "allow" then
        return not hit
    end
    if action == "deny" then
        return hit
    end
    return false
end

local function cityOf()
    local ip = ngx.ctx and ngx.ctx.ip
    if not ip or ip == "unknown" then
        ip = ngx.var.remote_addr
    end
    if not ip or ip == "" then
        return ""
    end
    local success, rec = pcall(mmdb.lookup, "geo_ip", ip)
    if not success or type(rec) ~= "table" then
        return ""
    end
    local city = rec.city
    if type(city) ~= "table" then
        return ""
    end
    return city.en or city["zh-CN"] or city.zh or ""
end

local M = {}

function M.evaluate(location, cfg)
    -- 原模块优先：命中即保留原判定（true, "region"|"province", 值）
    local r1, r2, r3 = original.evaluate(location, cfg)
    if r1 then
        return r1, r2, r3
    end

    if type(cfg) ~= "table" then
        return false
    end
    local rules = cfg.cityRules
    if type(rules) ~= "table" or #rules == 0 then
        return false
    end
    -- 城市只在 CN 范围内判定，避免国外 IP 被 allow 策略误伤
    if type(location) ~= "table" or location.iso ~= "CN" then
        return false
    end
    local city = cityOf()
    if city == "" then
        return false
    end
    if blocked(cfg.cityAction, inList(rules, city)) then
        return true, "city", city
    end
    return false
end

return M
