package v2

// 1Panel v2.x 社区版 WAF「地区访问限制 / CDN 真实 IP」策略层（补丁文件，新增）
//
// 结构来自对 1pwaf 容器内 Lua 字节码的反汇编 + 真机探针（2026-11-16）：
//
//	docker exec 1Panel-openresty-xxx /usr/local/openresty/luajit/bin/luajit \
//	    -bl /usr/local/openresty/1pwaf/lib/location_restrict.lua
//
// geoRestrict 合法形态（9/9 + 5/5 探针全绿）：
//
//	{
//	  "state":"on", "type":"geoRestrict", "res":"geo", "code":403,
//	  "action":"deny",                // 国家层：deny=命中即拦 / allow=名单外拦
//	  "rules":["CN","US"],            // 纯字符串数组（国家 iso），不是对象数组
//	  "schemaVersion":2,              // 必须=2，否则省份层整段跳过
//	  "provinceAction":"deny",
//	  "provinceRules":["Zhejiang"]    // province.en 英文全名
//	}
//
// 作用域：全局 geoRestrict.state 只是总开关，真正的规则在站点 config.json 里。
//   - 全局 on + 站点 on + 站点有规则 -> 拦截
//   - 全局 off 或 站点 off             -> 不拦
//   - 全局有规则 + 站点 off            -> 不拦（全局规则只做新建站点模板）
//
// cdn 合法形态（config.lua:get_real_ip 反汇编）：
//
//	{"state":"on","type":"headers","rules":[{"rule":"x-real-ip","state":"on"}]}
//
// 要求 全局 cdn.state=on **且** 站点 cdn.state=on，且 rules 必须内联在站点
// config.json 的 cdn 对象里（放 sites/<key>/rules/cdn.json 是读不到的）。
// type 可选 headers / header / xff / xff2 / xff3。

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------------- 选项表 ----------------

var wafGeoCountries = [][3]string{
	{"CN", "China", "中国"}, {"HK", "Hong Kong", "中国香港"}, {"MO", "Macao", "中国澳门"},
	{"TW", "Taiwan", "中国台湾"}, {"US", "United States", "美国"}, {"JP", "Japan", "日本"},
	{"KR", "South Korea", "韩国"}, {"KP", "North Korea", "朝鲜"}, {"RU", "Russia", "俄罗斯"},
	{"IN", "India", "印度"}, {"ID", "Indonesia", "印度尼西亚"}, {"MY", "Malaysia", "马来西亚"},
	{"SG", "Singapore", "新加坡"}, {"TH", "Thailand", "泰国"}, {"VN", "Vietnam", "越南"},
	{"PH", "Philippines", "菲律宾"}, {"MM", "Myanmar", "缅甸"}, {"KH", "Cambodia", "柬埔寨"},
	{"LA", "Laos", "老挝"}, {"BD", "Bangladesh", "孟加拉国"}, {"PK", "Pakistan", "巴基斯坦"},
	{"LK", "Sri Lanka", "斯里兰卡"}, {"NP", "Nepal", "尼泊尔"}, {"MN", "Mongolia", "蒙古"},
	{"KZ", "Kazakhstan", "哈萨克斯坦"}, {"AE", "United Arab Emirates", "阿联酋"},
	{"SA", "Saudi Arabia", "沙特阿拉伯"}, {"IL", "Israel", "以色列"}, {"TR", "Turkey", "土耳其"},
	{"IR", "Iran", "伊朗"}, {"IQ", "Iraq", "伊拉克"}, {"GB", "United Kingdom", "英国"},
	{"DE", "Germany", "德国"}, {"FR", "France", "法国"}, {"IT", "Italy", "意大利"},
	{"ES", "Spain", "西班牙"}, {"PT", "Portugal", "葡萄牙"}, {"NL", "Netherlands", "荷兰"},
	{"BE", "Belgium", "比利时"}, {"CH", "Switzerland", "瑞士"}, {"AT", "Austria", "奥地利"},
	{"SE", "Sweden", "瑞典"}, {"NO", "Norway", "挪威"}, {"DK", "Denmark", "丹麦"},
	{"FI", "Finland", "芬兰"}, {"PL", "Poland", "波兰"}, {"CZ", "Czechia", "捷克"},
	{"HU", "Hungary", "匈牙利"}, {"RO", "Romania", "罗马尼亚"}, {"GR", "Greece", "希腊"},
	{"IE", "Ireland", "爱尔兰"}, {"UA", "Ukraine", "乌克兰"}, {"BY", "Belarus", "白俄罗斯"},
	{"CA", "Canada", "加拿大"}, {"MX", "Mexico", "墨西哥"}, {"BR", "Brazil", "巴西"},
	{"AR", "Argentina", "阿根廷"}, {"CL", "Chile", "智利"}, {"CO", "Colombia", "哥伦比亚"},
	{"PE", "Peru", "秘鲁"}, {"VE", "Venezuela", "委内瑞拉"}, {"AU", "Australia", "澳大利亚"},
	{"NZ", "New Zealand", "新西兰"}, {"ZA", "South Africa", "南非"}, {"EG", "Egypt", "埃及"},
	{"NG", "Nigeria", "尼日利亚"}, {"KE", "Kenya", "肯尼亚"}, {"MA", "Morocco", "摩洛哥"},
}

// 省份值必须与 mmdb 里的 province.en 一致（GeoIP.mmdb 来自 MaxMind 命名）
var wafGeoProvinces = [][2]string{
	{"Beijing", "北京"}, {"Tianjin", "天津"}, {"Hebei", "河北"}, {"Shanxi", "山西"},
	{"Inner Mongolia", "内蒙古"}, {"Liaoning", "辽宁"}, {"Jilin", "吉林"},
	{"Heilongjiang", "黑龙江"}, {"Shanghai", "上海"}, {"Jiangsu", "江苏"},
	{"Zhejiang", "浙江"}, {"Anhui", "安徽"}, {"Fujian", "福建"}, {"Jiangxi", "江西"},
	{"Shandong", "山东"}, {"Henan", "河南"}, {"Hubei", "湖北"}, {"Hunan", "湖南"},
	{"Guangdong", "广东"}, {"Guangxi", "广西"}, {"Hainan", "海南"}, {"Chongqing", "重庆"},
	{"Sichuan", "四川"}, {"Guizhou", "贵州"}, {"Yunnan", "云南"}, {"Xizang", "西藏"},
	{"Shaanxi", "陕西"}, {"Gansu", "甘肃"}, {"Qinghai", "青海"}, {"Ningxia", "宁夏"},
	{"Xinjiang", "新疆"}, {"Hong Kong", "香港"}, {"Macao", "澳门"}, {"Taiwan", "台湾"},
}

// WafGeoOptions GET /api/v2/waf-log/geo/options
func (b *BaseApi) WafGeoOptions(c *gin.Context) {
	countries := make([]gin.H, 0, len(wafGeoCountries))
	for _, it := range wafGeoCountries {
		countries = append(countries, gin.H{"iso": it[0], "en": it[1], "zh": it[2]})
	}
	provinces := make([]gin.H, 0, len(wafGeoProvinces))
	for _, it := range wafGeoProvinces {
		provinces = append(provinces, gin.H{"en": it[0], "zh": it[1]})
	}
	globalState := "off"
	if conf := wafConfDir(); conf != "" {
		if g, _, err := wafReadJSONMap(filepath.Join(conf, "global.json")); err == nil {
			if geo, ok := g["geoRestrict"].(map[string]interface{}); ok {
				if st, _ := geo["state"].(string); st == "on" {
					globalState = "on"
				}
			}
		}
	}
	wafOK(c, gin.H{
		"ok": true, "countries": countries, "provinces": provinces,
		"global_geo_state": globalState,
	})
}

// ---------------- 读写策略 ----------------

func wafPolicyPath(scope, key, name string) (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("未找到 1pwaf 配置目录")
	}
	if scope == "global" {
		return filepath.Join(conf, "global.json"), nil
	}
	if !wafSafeKey(key) {
		return "", fmt.Errorf("站点标识不合法")
	}
	p := filepath.Join(wafSiteDir(wafDataDir(conf), key), "config.json")
	if !wafPathExists(p) {
		return "", fmt.Errorf("站点配置不存在：%s", p)
	}
	return p, nil
}

// WafPolicyGet GET /api/v2/waf-log/policy?scope=site|global&key=&name=geoRestrict|cdn
func (b *BaseApi) WafPolicyGet(c *gin.Context) {
	scope := c.DefaultQuery("scope", "site")
	name := c.Query("name")
	if name != "geoRestrict" && name != "cdn" {
		wafBad(c, "name 只能是 geoRestrict / cdn")
		return
	}
	p, err := wafPolicyPath(scope, c.Query("key"), name)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	m, _, err := wafReadJSONMap(p)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	val, _ := m[name].(map[string]interface{})
	res := gin.H{"ok": true, "scope": scope, "name": name, "value": wafEmptyIfNil(val)}
	if scope == "site" {
		// 附带全局默认，前端展示「全局默认」用
		if conf := wafConfDir(); conf != "" {
			if g, _, err := wafReadJSONMap(filepath.Join(conf, "global.json")); err == nil {
				gv, _ := g[name].(map[string]interface{})
				res["global"] = wafEmptyIfNil(gv)
			}
		}
	}
	wafOKData(c, res)
}

type wafPolicyReq struct {
	Scope  string                 `json:"scope"`
	Key    string                 `json:"key"`
	Name   string                 `json:"name"`
	Value  map[string]interface{} `json:"value"`
	Reload bool                   `json:"reload"`
}

// wafPolicyApply 真正的落盘逻辑（Save 与 Reset 共用，避免二次绑定 body）
func wafPolicyApply(scope, key, name string, value map[string]interface{}, reload bool) (gin.H, error) {
	p, err := wafPolicyPath(scope, key, name)
	if err != nil {
		return nil, err
	}
	norm := value
	if name == "geoRestrict" {
		norm = wafNormGeo(value)
	} else {
		norm = wafNormCdn(value)
	}
	m, _, err := wafReadJSONMap(p)
	if err != nil {
		return nil, err
	}
	m[name] = norm
	backup, _ := wafBackupFile(p)
	if err := wafWriteJSONMap(p, m); err != nil {
		return nil, err
	}
	// 站点 cdn 同步一份到 rules/cdn.json，保持规则库列表一致
	if name == "cdn" && scope == "site" && wafSafeKey(key) {
		if conf := wafConfDir(); conf != "" {
			rp := filepath.Join(wafSiteDir(wafDataDir(conf), key), "rules", "cdn.json")
			if wafPathExists(rp) {
				_ = wafWriteJSONMap(rp, norm)
			}
		}
	}
	res := gin.H{"saved": true, "path": p, "value": norm}
	if backup != "" {
		res["backup"] = backup
	}
	if reload {
		out, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = out
		if len(w) > 0 {
			res["warnings"] = w
		}
		if err == nil {
			time.Sleep(900 * time.Millisecond)
		}
	}
	return res, nil
}

// WafPolicySave POST /api/v2/waf-log/policy
func (b *BaseApi) WafPolicySave(c *gin.Context) {
	var req wafPolicyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	if req.Name != "geoRestrict" && req.Name != "cdn" {
		wafBad(c, "name 只能是 geoRestrict / cdn")
		return
	}
	if req.Scope != "global" && req.Scope != "site" {
		wafBad(c, "scope 只能是 global / site")
		return
	}
	res, err := wafPolicyApply(req.Scope, req.Key, req.Name, req.Value, req.Reload)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	wafOKData(c, res)
}

// WafPolicyReset POST /api/v2/waf-log/policy/reset {scope:"site",key,name}
// 站点策略继承全局默认（state 强制 off，避免一继承就全站生效）
func (b *BaseApi) WafPolicyReset(c *gin.Context) {
	var req wafPolicyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	if req.Name != "geoRestrict" && req.Name != "cdn" {
		wafBad(c, "name 只能是 geoRestrict / cdn")
		return
	}
	conf := wafConfDir()
	if conf == "" {
		wafFailErr(c, fmt.Errorf("未找到 1pwaf 配置目录"))
		return
	}
	g, _, err := wafReadJSONMap(filepath.Join(conf, "global.json"))
	if err != nil {
		wafFailErr(c, err)
		return
	}
	gv, _ := g[req.Name].(map[string]interface{})
	if gv == nil {
		wafBad(c, "全局没有该配置可继承")
		return
	}
	cp := map[string]interface{}{}
	for k, v := range gv {
		cp[k] = v
	}
	cp["state"] = "off"
	res, err := wafPolicyApply("site", req.Key, req.Name, cp, true)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	wafOKData(c, res)
}

// ---------------- 归一化 ----------------

func wafOK(c *gin.Context, data gin.H)   { c.JSON(200, gin.H{"code": 200, "message": "", "data": data}) }
func wafOKData(c *gin.Context, d gin.H) { wafOK(c, d) }
func wafFailErr(c *gin.Context, err error) {
	c.JSON(500, gin.H{"code": 500, "message": err.Error(), "data": nil})
}

func wafEmptyIfNil(v map[string]interface{}) map[string]interface{} {
	if v == nil {
		return map[string]interface{}{}
	}
	return v
}

func wafStrList(v interface{}) []string {
	out := make([]string, 0, 8)
	seen := map[string]bool{}
	switch t := v.(type) {
	case []interface{}:
		for _, it := range t {
			if s, ok := it.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	case []string:
		for _, s := range t {
			s = strings.TrimSpace(s)
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	case string:
		for _, s := range strings.Split(t, ",") {
			s = strings.TrimSpace(s)
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func wafOnOff(v interface{}, def string) string {
	if s, ok := v.(string); ok {
		if s == "on" || s == "off" {
			return s
		}
	}
	return def
}

// wafNormGeo 按实测结构归一化：rules 只能是字符串数组，schemaVersion 固定 2
func wafNormGeo(in map[string]interface{}) map[string]interface{} {
	act := "deny"
	if s, _ := in["action"].(string); s == "allow" || s == "deny" {
		act = s
	}
	rules := wafStrList(in["rules"])
	for i, s := range rules {
		rules[i] = strings.ToUpper(s)
	}
	out := map[string]interface{}{
		"state":         wafOnOff(in["state"], "off"),
		"type":          "geoRestrict",
		"res":           "geo",
		"code":          403,
		"action":        act,
		"rules":         rules,
		"schemaVersion": 2,
	}
	if prov := wafStrList(in["provinceRules"]); len(prov) > 0 {
		pact := "deny"
		if s, _ := in["provinceAction"].(string); s == "allow" || s == "deny" {
			pact = s
		}
		out["provinceRules"] = prov
		out["provinceAction"] = pact
	}
	// 城市：留空即不限制（补丁 Lua 里 #cityRules==0 直接跳过）
	if cities := wafStrList(in["cityRules"]); len(cities) > 0 {
		cact := "deny"
		if s, _ := in["cityAction"].(string); s == "allow" || s == "deny" {
			cact = s
		}
		out["cityRules"] = cities
		out["cityAction"] = cact
	}
	return out
}

// wafNormCdn 真实 IP 获取方式归一化
func wafNormCdn(in map[string]interface{}) map[string]interface{} {
	typ := "headers"
	switch s, _ := in["type"].(string); s {
	case "headers", "header", "xff", "xff2", "xff3":
		typ = s
	}
	out := map[string]interface{}{
		"state": wafOnOff(in["state"], "off"),
		"type":  typ,
	}
	switch typ {
	case "header":
		h := "x-real-ip"
		if s, _ := in["header"].(string); strings.TrimSpace(s) != "" {
			h = strings.ToLower(strings.TrimSpace(s))
		}
		out["header"] = h
	case "headers":
		items := make([]map[string]interface{}, 0, 16)
		seen := map[string]bool{}
		raw, _ := in["rules"].([]interface{})
		for _, it := range raw {
			var name, st string
			switch o := it.(type) {
			case string:
				name, st = o, "on"
			case map[string]interface{}:
				name, _ = o["rule"].(string)
				st = wafOnOff(o["state"], "on")
			}
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			items = append(items, map[string]interface{}{"rule": name, "state": st})
		}
		out["rules"] = items
	}
	return out
}

// wafJSONPretty 调试用
func wafJSONPretty(v interface{}) string {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(buf)
}
