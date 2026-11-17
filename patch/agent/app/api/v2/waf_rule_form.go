package v2

// 1Panel v2.x 社区版 WAF「图形化规则表单 → 1pwaf 规则库」编译器（补丁文件，新增）
//
// 官方创建规则表单是：匹配对象 / 匹配条件 / 匹配内容 / 动作 / 返回状态码。
// 1pwaf 没有这样的中间表示，只有一堆「按位置分文件 + 隐式正则」的规则库，所以这里做一层翻译：
//
//	匹配对象     动作=禁止              动作=允许
//	URL          urlBlack(dirFilter)    urlWhite(dirFilter)
//	User-Agent   uaBlack                uaWhite
//	Header       header(appFilter)      —（1pwaf 没有 header 白名单）
//	Cookie       cookie                 —
//	参数         args                   —
//	请求方法     —                      methodWhite(httpMethod)
//	来源 IP      ipBlack/ipArr          ipWhite/ipArr
//	Host         —                      —
//
// 匹配条件编译成 PCRE（1pwaf 用 ngx.re，实测支持负向断言）：
//
//	等于     ^V$            不等于   ^(?!V$).*$
//	包含     V              不包含   ^(?!.*V).*$
//	正则     V（原样）
//
// 注意：官方「多行 = AND」，1pwaf 单条规则只能带一个条件，多行会展开成多条规则 = OR，
// 这里会明确告警，不做假承诺。

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// 对象 → 允许/禁止 对应的规则文件与默认 type
type wafFormTarget struct {
	File string
	Type string
}

var wafFormObjects = map[string]struct {
	Label   string
	Deny    *wafFormTarget
	Allow   *wafFormTarget
	NoRegex bool // 值不是正则（method / fileExt / ip）
	Tip     string
}{
	"url":  {"URL", &wafFormTarget{"urlBlack", "dirFilter"}, &wafFormTarget{"urlWhite", "dirFilter"}, false, "匹配请求 URI，如 /admin 或 \\.php$"},
	"ua":   {"User-Agent", &wafFormTarget{"uaBlack", "scannerFilter"}, &wafFormTarget{"uaWhite", "scannerFilter"}, false, "匹配 User-Agent"},
	"header": {"Header 值", &wafFormTarget{"header", "appFilter"}, nil, false,
		"只能按「请求头的值」匹配，不能按名称；内容填值即可"},
	"cookie": {"Cookie", &wafFormTarget{"cookie", "scannerFilter"}, nil, false, "匹配 Cookie 原文"},
	"args":   {"请求参数", &wafFormTarget{"args", "oneWordTrojan"}, nil, false, "匹配参数里的特征串"},
	"method": {"请求方法", nil, &wafFormTarget{"methodWhite", "httpMethod"}, true,
		"methodWhite 是「允许的方法」列表，只能用于「允许」动作"},
	"ip": {"来源 IP", &wafFormTarget{"ipBlack", "ipArr"}, &wafFormTarget{"ipWhite", "ipArr"}, true,
		"支持单 IP、CIDR、a-b 区间"},
	"fileExt": {"文件后缀", &wafFormTarget{"fileExt", "fileExt"}, nil, true, "只写后缀名，如 bak、sql（不用带点）"},
	"host": {"Host", nil, nil, true, "1pwaf 没有按 Host 拦截的规则文件，建议用站点级黑名单或地区限制"},
}

// wafEscRegex 转义正则元字符，保证「等于 / 包含」按字面量匹配
func wafEscRegex(s string) string {
	return regexp.QuoteMeta(s)
}

// wafCompileCond 把条件 + 值编译成 1pwaf 里实际生效的 PCRE
//
// 实测（2026-11-16 站点 测试站点，逐条隔离测试）：
//   ^/eqtest$            只命中 /eqtest           ✅ 等于
//   /eqtest              命中含该串的任意路径      ✅ 包含
//   ^/(?!neq$).*$        /neq 不拦，其余全拦      ✅ 不等于（URL）
//   ^(?!neq$).*$         连 /neq 也拦            ❌ 1pwaf 对 URL 规则会去掉行首 ^ 语义
//   ^(?!.*requests).*$   UA 不包含 requests      ✅ 不包含（UA 实测）
func wafCompileCond(cond, v, object string) (string, error) {
	switch cond {
	case "eq":
		return "^" + wafEscRegex(v) + "$", nil
	case "ne":
		if object != "url" {
			return "", fmt.Errorf("「不等于」只有 URL 对象能可靠翻译（1pwaf 对其它对象会误拦），请改用「不包含」或白名单")
		}
		q := wafEscRegex(v)
		if strings.HasPrefix(v, "/") {
			// /x → ^/(?!x$).*$
			return "^/(?!" + strings.TrimPrefix(q, `/`) + "$).*$", nil
		}
		return "^(?!" + q + "$).*$", nil
	case "contain":
		return wafEscRegex(v), nil
	case "notContain":
		return "^(?!.*" + wafEscRegex(v) + ").*$", nil
	case "regex":
		if _, err := regexp.Compile(v); err != nil {
			return "", fmt.Errorf("正则不合法：%v", err)
		}
		return v, nil
	}
	return "", fmt.Errorf("未知匹配条件：%s", cond)
}

type wafFormReq struct {
	Key     string   `json:"key"`     // 空=全局
	Object  string   `json:"object"`  // url|ua|header|cookie|args|method|ip|host
	Cond    string   `json:"cond"`    // eq|ne|contain|notContain|regex
	Values  []string `json:"values"`  // 多行
	Action  string   `json:"action"`  // deny|allow
	Name    string   `json:"name"`    // 备注
	State   string   `json:"state"`   // on|off
	Preview bool     `json:"preview"` // true=只编译不写盘
	Reload  bool     `json:"reload"`
	Code    int      `json:"code"` // 站点级返回状态码，0=不改
}

// wafFormDefaultType 取该文件里已有规则的 type，保持与内置条目一致
func wafFormDefaultType(dir, file, fallback string) string {
	rules, err := wafRuleReadRaw(dir, file)
	if err == nil {
		for _, r := range rules {
			if t := wafStr(r["type"]); t != "" {
				return t
			}
		}
	}
	return fallback
}

// WafRuleCompile POST /api/v2/waf-log/rule/compile
// 把表单翻译成 1pwaf 规则条目；preview=true 时只返回编译结果
func (b *BaseApi) WafRuleCompile(c *gin.Context) {
	var req wafFormReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	obj, ok := wafFormObjects[req.Object]
	if !ok {
		wafBad(c, "未知匹配对象："+req.Object)
		return
	}
	var tgt *wafFormTarget
	switch req.Action {
	case "allow":
		tgt = obj.Allow
	case "", "deny":
		tgt = obj.Deny
	default:
		wafBad(c, "动作只能是 deny / allow")
		return
	}
	if tgt == nil {
		wafBad(c, fmt.Sprintf("1pwaf 不支持「%s + %s」的组合：%s", obj.Label,
			map[string]string{"allow": "允许", "deny": "禁止"}[req.Action], obj.Tip))
		return
	}
	if req.Key != "" {
		// 站点侧只有 defaultUrlBlack / defaultUaBlack 这类文件，做一次名字映射
		tgt = &wafFormTarget{File: wafFormSiteFile(tgt.File), Type: tgt.Type}
		if !wafSiteRuleFileValid(tgt.File) {
			wafBad(c, "该规则文件不支持站点级配置："+tgt.File)
			return
		}
	}

	vals := make([]string, 0, len(req.Values))
	for _, v := range req.Values {
		v = strings.TrimSpace(v)
		if v != "" {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		wafBad(c, "匹配内容不能为空")
		return
	}

	dir, err := wafRuleDirFor(req.Key)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	if req.Key != "" && !wafPathExists(filepath.Join(dir, tgt.File+".json")) {
		wafBad(c, "站点下没有该规则文件："+tgt.File+".json")
		return
	}

	type row struct {
		Rule  string `json:"rule"`
		Start string `json:"start,omitempty"`
		End   string `json:"end,omitempty"`
		Type  string `json:"type"`
	}
	rows := make([]row, 0, len(vals))
	warns := make([]string, 0, 4)

	for _, v := range vals {
		switch req.Object {
		case "ip":
			start, end, err := wafIPv4Range(v)
			if err != nil {
				wafBad(c, err.Error())
				return
			}
			rows = append(rows, row{Rule: wafIPv4Display(start, end), Start: start, End: end, Type: tgt.Type})
		case "method":
			rows = append(rows, row{Rule: strings.ToUpper(v), Type: tgt.Type})
		case "fileExt":
			// 只存后缀名，去掉前导点
			rows = append(rows, row{Rule: strings.TrimPrefix(strings.ToLower(v), "."), Type: tgt.Type})
		default:
			cond := req.Cond
			if cond == "" {
				cond = "contain"
			}
			re, err := wafCompileCond(cond, v, req.Object)
			if err != nil {
				wafBad(c, err.Error())
				return
			}
			rows = append(rows, row{Rule: re, Type: tgt.Type})
		}
	}

	if len(vals) > 1 {
		warns = append(warns, fmt.Sprintf(
			"官方表单里多行是「同时满足（AND）」，1pwaf 一条规则只能带一个条件，这里已展开成 %d 条规则（满足任一即命中，OR）",
			len(vals)))
	}
	if req.Object == "header" {
		warns = append(warns, "1pwaf 只把所有请求头的值拼在一起做正则，无法按「头名称」限制；如果不同头的值可能重复，请写更精确的正则")
	}
	if req.Cond == "ne" || req.Cond == "notContain" {
		if req.Cond == "ne" {
			warns = append(warns, "「不等于」在 URL 上编译为 ^/(?!...).*$（实测这是 1pwaf 唯一正确的写法）")
		} else {
			warns = append(warns, "「不包含」编译为 ^(?!.*...).*$；URL 与 UA 上已实测可用，其它对象建议保存后实测一次")
		}
	}

	preview := gin.H{"ok": true, "file": tgt.File, "type": tgt.Type, "rows": rows, "count": len(rows), "warnings": warns}
	if req.Preview {
		wafOKData(c, preview)
		return
	}

	// 落盘
	rules, err := wafRuleReadRaw(dir, tgt.File)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	state := req.State
	if state != "off" {
		state = "on"
	}
	name := strings.TrimSpace(req.Name)
	added := 0
	for _, r := range rows {
		entry := map[string]interface{}{"state": state, "type": r.Type}
		if name != "" {
			entry["name"] = name
		}
		if r.Start != "" {
			entry["ipStart"] = r.Start
			entry["ipEnd"] = r.End
		} else {
			entry["rule"] = r.Rule
		}
		rules = append(rules, entry)
		added++
	}
	backup, err := wafRuleWriteRaw(dir, tgt.File, rules)
	if err != nil {
		wafBwFail(c, err)
		return
	}

	res := gin.H{"ok": true, "saved": true, "file": tgt.File, "type": tgt.Type,
		"added": added, "count": len(rules), "backup": backup, "rows": rows, "warnings": warns}

	// 站点级状态码（模块级共享，命中该模块的任意规则都按此码返回）
	if req.Code > 0 {
		if req.Key == "" {
			warns = append(warns, "返回状态码只对站点生效，本次是全局规则，已忽略状态码")
		} else if code, ok := wafAllowedRuleCode(req.Code); ok {
			if err := wafSetSiteModuleCode(req.Key, tgt.File, code); err != nil {
				warns = append(warns, "写入返回状态码失败："+err.Error())
			} else {
				res["code"] = code
				if code == 444 {
					warns = append(warns, "444 表示直接断开连接（curl 会显示 000）")
				}
			}
		} else {
			warns = append(warns, fmt.Sprintf("状态码 %d 不受支持，已忽略", req.Code))
		}
	}

	if req.Reload {
		out, w, rerr := wafReloadConf()
		res["reload_output"] = out
		res["reloaded"] = rerr == nil
		warns = append(warns, w...)
	}
	if len(warns) > 0 {
		res["warnings"] = warns
	}
	wafOKData(c, res)
}

// wafFormSiteFile 全局规则文件 → 站点侧同名文件
func wafFormSiteFile(file string) string {
	switch file {
	case "urlBlack":
		return "defaultUrlBlack"
	case "uaBlack":
		return "defaultUaBlack"
	}
	return file
}

// 实测可用的状态码（写进站点 config.json 对应模块的 code 字段）
func wafAllowedRuleCode(n int) (int, bool) {
	switch n {
	case 400, 403, 404, 444, 500, 503, 504:
		return n, true
	}
	return 0, false
}

// wafSetSiteModuleCode 给站点 config.json 里某个模块写 code
// 注意：状态码是「模块级」的——同一文件下所有规则命中都按这个码返回。
func wafSetSiteModuleCode(key, file string, code int) error {
	conf := wafConfDir()
	if conf == "" {
		return fmt.Errorf("没找到 1pwaf 配置目录")
	}
	if !wafSafeKey(key) {
		return fmt.Errorf("站点标识不合法")
	}
	// 站点 config.json 里的模块名与站点规则文件名一一对应
	// （站点只有 defaultUrlBlack / defaultUaBlack，没有全局的 urlBlack / uaBlack）
	scope := file
	switch file {
	case "urlWhite":
		scope = "defaultUrlBlack"
	case "uaWhite":
		scope = "defaultUaBlack"
	}
	if !wafSiteScopeKeys[scope] {
		return fmt.Errorf("站点配置不支持模块 %s", scope)
	}
	path := filepath.Join(wafSiteDir(wafDataDir(conf), key), "config.json")
	if !wafPathExists(path) {
		return fmt.Errorf("站点配置文件不存在：%s", path)
	}
	m, _, err := wafReadJSONMap(path)
	if err != nil {
		return err
	}
	var mod map[string]interface{}
	if v, ok := m[scope]; ok {
		if obj, isMap := v.(map[string]interface{}); isMap {
			mod = obj
		}
	}
	if mod == nil {
		mod = map[string]interface{}{"type": scope, "state": "on"}
	}
	mod["code"] = code
	m[scope] = mod
	_, _ = wafBackupFile(path)
	return wafWriteJSONMap(path, m)
}
