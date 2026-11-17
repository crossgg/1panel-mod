package v2

// 1Panel v2.x 社区版 WAF「城市级地区限制」后端（补丁文件，新增）
//
// 三个能力：
//   GET  /geo/cities          从 GeoIP.mmdb 枚举中国城市（city.en / city.zh），带文件缓存
//   GET  /geo/city/status     检查 Lua 补丁是否已应用
//   POST /geo/city/patch      把 location_restrict.lua 写进挂载卷 + 改 waf.conf + reload
//
// 关键事实（真机实测）：
//   - 镜像自带的 GeoIP.mmdb 只有 iso/country/province/lat/lon，**没有 city**。
//     要启用城市限制，需先在「IP 库」页下载 P3TERX GeoLite2-City.mmdb 并自动转换。
//   - 官方 geoip.lookup() 丢掉 city，location_restrict.evaluate() 只比较 iso 与 province.en。
//     所以补丁 Lua 用 ngx.ctx.ip 再查一次原始 mmdb 记录。
//   - waf.conf 位于宿主机挂载卷，里面定义了 lua_package_path；在前面插入补丁目录即可
//     让 require "location_restrict" 优先命中我们放在挂载卷里的明文 Lua。
//     不需要 docker cp / docker commit / 重建镜像，容器重建也不丢。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
)

const wafCityLuaPathMarker = "/usr/local/openresty/1pwaf/data/lua/?.lua;"

// wafCityLua 是写给宿主机挂载卷的明文 Lua（LuaJIT 可直接加载源码，无需编译）。
// 与 patch/lua/location_restrict.lua 保持一致。
const wafCityLua = `-- 1pwaf 城市级地区限制补丁（包装官方模块，不改原有行为）
local ORIGINAL = "/usr/local/openresty/1pwaf/lib/location_restrict.lua"
local ok, original = pcall(dofile, ORIGINAL)
if not ok or type(original) ~= "table" or type(original.evaluate) ~= "function" then
    return { evaluate = function() return false end }
end
local mmdb = require "resty.maxminddb"
local function inList(list, value)
    if type(list) ~= "table" or not value or value == "" then return false end
    for _, v in ipairs(list) do if v == value then return true end end
    return false
end
local function blocked(action, hit)
    if action == "allow" then return not hit end
    if action == "deny" then return hit end
    return false
end
local function cityOf()
    local ip = ngx.ctx and ngx.ctx.ip
    if not ip or ip == "unknown" then ip = ngx.var.remote_addr end
    if not ip or ip == "" then return "" end
    local success, rec = pcall(mmdb.lookup, "geo_ip", ip)
    if not success or type(rec) ~= "table" then return "" end
    local city = rec.city
    if type(city) ~= "table" then return "" end
    return city.en or city["zh-CN"] or city.zh or ""
end
local M = {}
function M.evaluate(location, cfg)
    local r1, r2, r3 = original.evaluate(location, cfg)
    if r1 then return r1, r2, r3 end
    if type(cfg) ~= "table" then return false end
    local rules = cfg.cityRules
    if type(rules) ~= "table" or #rules == 0 then return false end
    if type(location) ~= "table" or location.iso ~= "CN" then return false end
    local city = cityOf()
    if city == "" then return false end
    if blocked(cfg.cityAction, inList(rules, city)) then return true, "city", city end
    return false
end
return M
`

type wafCityItem struct {
	En string `json:"en"`
	Zh string `json:"zh"`
}

// WafGeoCities GET /waf-log/geo/cities
func (b *BaseApi) WafGeoCities(c *gin.Context) {
	conf := wafConfDir()
	if conf == "" {
		wafOK(c, gin.H{"ready": false, "cities": []wafCityItem{}, "hint": "没找到 1pwaf 数据目录"})
		return
	}
	data := wafDataDir(conf)
	mmdbPath := filepath.Join(data, "geo", "GeoIP.mmdb")
	cachePath := filepath.Join(conf, "cities.json")

	st, err := os.Stat(mmdbPath)
	if err != nil {
		wafOK(c, gin.H{"ready": false, "cities": []wafCityItem{}, "hint": "GeoIP.mmdb 不存在"})
		return
	}
	// 缓存只要比 mmdb 新就直接读（换库后自动失效）
	if cs, err := os.Stat(cachePath); err == nil && !cs.ModTime().Before(st.ModTime()) {
		if raw, err := os.ReadFile(cachePath); err == nil {
			var items []wafCityItem
			if json.Unmarshal(raw, &items) == nil {
				chint := ""
				if len(items) == 0 {
					chint = "当前 GeoIP.mmdb 不含城市信息（镜像自带的是国家/省份库）。请在「IP 库」页下载 GeoLite2-City.mmdb 并自动转换后再使用城市限制。"
				}
				wafOK(c, gin.H{"ready": len(items) > 0, "cached": true, "cities": items,
					"count": len(items), "hint": chint})
				return
			}
		}
	}

	r, err := maxminddb.Open(mmdbPath)
	if err != nil {
		wafOK(c, gin.H{"ready": false, "cities": []wafCityItem{}, "hint": "GeoIP.mmdb 打开失败：" + err.Error()})
		return
	}
	defer r.Close()

	seen := make(map[string]string, 512)
	it := r.Networks()
	for it.Next() {
		var rec wafGeoFlat
		if _, err := it.Network(&rec); err != nil || rec.Iso != "CN" {
			continue
		}
		en, zh := rec.City.En, rec.City.Zh
		if zh == "" {
			zh = rec.City.ZhCN
		}
		if en == "" {
			en = zh
		}
		if en == "" {
			continue
		}
		if _, ok := seen[en]; !ok {
			seen[en] = zh
		}
	}
	items := make([]wafCityItem, 0, len(seen))
	for en, zh := range seen {
		if zh == "" {
			zh = en
		}
		items = append(items, wafCityItem{En: en, Zh: zh})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].En < items[j].En })

	_ = os.WriteFile(cachePath+".tmp", []byte(func() string {
		b, _ := json.Marshal(items)
		return string(b)
	}()), 0644)
	_ = os.Rename(cachePath+".tmp", cachePath)

	hint := ""
	if len(items) == 0 {
		hint = "当前 GeoIP.mmdb 不含城市信息（镜像自带的是国家/省份库）。请在「IP 库」页下载 GeoLite2-City.mmdb 并自动转换后再使用城市限制。"
	}
	wafOK(c, gin.H{"ready": len(items) > 0, "cached": false, "cities": items, "count": len(items), "hint": hint})
}

// wafCityPatchPaths 返回宿主机挂载卷里的两个目标路径
func wafCityPatchPaths() (luaPath, confPath string, err error) {
	conf := wafConfDir()
	if conf == "" {
		return "", "", fmt.Errorf("没找到 1pwaf 数据目录")
	}
	data := wafDataDir(conf)
	return filepath.Join(data, "lua", "location_restrict.lua"), filepath.Join(conf, "waf.conf"), nil
}

// wafCityOpenRestyReady：1pwaf 数据目录 + waf.conf + 运行中的 openresty 容器
func wafCityOpenRestyReady() bool {
	conf := wafConfDir()
	if conf == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(conf, "waf.conf")); err != nil {
		return false
	}
	return len(wafFindContainers()) > 0
}

// WafGeoCityStatus GET /waf-log/geo/city/status
func (b *BaseApi) WafGeoCityStatus(c *gin.Context) {
	luaPath, confPath, err := wafCityPatchPaths()
	if err != nil {
		wafOK(c, gin.H{"applied": false, "hint": err.Error()})
		return
	}
	_, e1 := os.Stat(luaPath)
	raw, e2 := os.ReadFile(confPath)
	applied := e1 == nil && e2 == nil && strings.Contains(string(raw), wafCityLuaPathMarker)
	ready := wafCityOpenRestyReady()
	hint := ""
	if !ready {
		hint = "未检测到可用的 OpenResty：请先在面板「应用商店」安装 OpenResty，装好后再点「应用城市补丁」"
	} else if !applied {
		hint = "未应用城市补丁；点「应用城市补丁」后城市限制才会生效"
	}
	wafOK(c, gin.H{"applied": applied, "openresty_ready": ready, "lua": luaPath, "conf": confPath, "hint": hint})
}

// WafGeoCityPatch POST /waf-log/geo/city/patch
func (b *BaseApi) WafGeoCityPatch(c *gin.Context) {
	if !wafCityOpenRestyReady() {
		wafFailErr(c, fmt.Errorf("未检测到可用的 OpenResty：请先在面板「应用商店」安装 OpenResty，装好后再点「应用城市补丁」"))
		return
	}
	luaPath, confPath, err := wafCityPatchPaths()
	if err != nil {
		wafFailErr(c, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(luaPath), 0755); err != nil {
		wafFailErr(c, err)
		return
	}
	if err := os.WriteFile(luaPath+".tmp", []byte(wafCityLua), 0644); err != nil {
		wafFailErr(c, err)
		return
	}
	if err := os.Rename(luaPath+".tmp", luaPath); err != nil {
		wafFailErr(c, err)
		return
	}

	raw, err := os.ReadFile(confPath)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	text := string(raw)
	if !strings.Contains(text, wafCityLuaPathMarker) {
		// 只改 lua_package_path 这一行，其它指令原样保留
		lines := strings.Split(text, "\n")
		hit := false
		for i, line := range lines {
			if strings.Contains(line, "lua_package_path") && strings.Contains(line, "1pwaf/lib/?.lua") {
				lines[i] = strings.Replace(line, `"`, `"`+wafCityLuaPathMarker, 1)
				hit = true
				break
			}
		}
		if !hit {
			_ = os.Remove(luaPath)
			wafFailErr(c, fmt.Errorf("waf.conf 里没找到 lua_package_path，已回滚 Lua 文件"))
			return
		}
		if err := os.WriteFile(confPath+".tmp", []byte(strings.Join(lines, "\n")), 0644); err != nil {
			wafFailErr(c, err)
			return
		}
		if err := os.Rename(confPath+".tmp", confPath); err != nil {
			wafFailErr(c, err)
			return
		}
	}
	reloaded, warns, err := wafReloadConf()
	if err != nil {
		wafFailErr(c, fmt.Errorf("补丁已写入，但 nginx reload 失败：%v", err))
		return
	}
	wafOK(c, gin.H{"applied": true, "at": time.Now().Format("2006-01-02 15:04:05"),
		"lua": luaPath, "conf": confPath, "reloaded": reloaded, "warnings": warns})
}
