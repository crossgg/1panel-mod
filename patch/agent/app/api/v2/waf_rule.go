package v2

// 1Panel v2.x 社区版 WAF「自定义规则」API（补丁文件，新增）
//
// 1pwaf 没有独立的「自定义规则库」，所有可编辑规则都是 data/rules/*.json 里的
// {"rules":[{"state","name","rule","type"}, ...]}（IP 条目例外，见 waf_bw.go）。
// 因此本文件把「自定义规则」实现成统一规则库管理器：
//   - 汇总所有可编辑规则文件 → 一张表（搜索 / 筛选 / 启停 / 编辑 / 删除 / 新增）
//   - 新增时按「匹配位置」自动落到对应文件与 type，type 取值均为实测可用的：
//       URL 路径   → urlBlack.json   type=dirFilter
//       User-Agent → uaBlack.json    type=scannerFilter
//       参数       → args.json       type=oneWordTrojan
//       Header     → header.json     type=appFilter
//       Cookie     → cookie.json     type=scannerFilter
//       文件后缀   → fileExt.json    type=fileExt
//       HTTP 方法  → methodWhite.json type=httpMethod
//       IP         → ipBlack.json    type=ipArr（ipStart/ipEnd）

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// 允许在页面上管理的规则文件（app/ 与 vuln/ 是内置库，结构不同，不在此列）
var wafRuleFileOrder = []string{
	"urlBlack", "urlWhite", "uaBlack", "uaWhite", "ipBlack", "ipWhite",
	"args", "header", "cookie", "fileExt", "methodWhite", "defaultUrlBlack",
	"defaultUaBlack", "acl", "urlcc", "cdn",
}

var wafRuleFileLabel = map[string]string{
	"urlBlack":        "URL 黑名单",
	"urlWhite":        "URL 白名单",
	"uaBlack":         "UA 黑名单",
	"uaWhite":         "UA 白名单",
	"ipBlack":         "IP 黑名单",
	"ipWhite":         "IP 白名单",
	"args":            "参数检测",
	"header":          "Header 检测",
	"cookie":          "Cookie 检测",
	"fileExt":         "危险文件后缀",
	"methodWhite":     "HTTP 方法白名单",
	"defaultUrlBlack": "内置 URL 黑名单",
	"defaultUaBlack":  "内置 UA 黑名单",
	"acl":             "ACL 访问控制",
	"urlcc":           "URL 频率限制",
	"cdn":             "CDN 回源头",
}

// 新增规则时的「匹配位置」→ 目标文件 + type
type wafRuleTarget struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	File  string `json:"file"`
	Type  string `json:"type"`
	Tip   string `json:"tip"`
}

var wafRuleTargets = []wafRuleTarget{
	{"url", "URL 路径", "urlBlack", "dirFilter", "匹配请求 URI，支持正则，如 /admin 或 \\.php$"},
	{"ua", "User-Agent", "uaBlack", "scannerFilter", "匹配 User-Agent，支持正则，如 sqlmap"},
	{"args", "请求参数", "args", "oneWordTrojan", "匹配参数值里的攻击特征，支持正则"},
	{"header", "请求头", "header", "appFilter", "匹配任意请求头的值，支持正则"},
	{"cookie", "Cookie", "cookie", "scannerFilter", "匹配 Cookie 内容，支持正则"},
	{"fileExt", "文件后缀", "fileExt", "fileExt", "只写后缀名，如 bak、sql"},
	{"method", "HTTP 方法", "methodWhite", "httpMethod", "只写方法名，如 TRACE"},
	{"ip", "来源 IP", "ipBlack", "ipArr", "支持单 IP、CIDR、a-b 区间"},
}

func wafRuleFileValid(f string) bool {
	for _, n := range wafRuleFileOrder {
		if n == f {
			return true
		}
	}
	return false
}

// 站点规则目录里真实存在、且确实参与检测的文件（2026-11-16 真机实测）
//   defaultUrlBlack → URL 拦截（403 ✅）
//   header          → Header 拦截（403 ✅）
//   fileExt         → 上传后缀（仅对 POST 上传体生效）
//   acl             → 本版 1pwaf 的 acl.json 未接入检测流程（实测 404/不拦），不开放
var wafSiteRuleFiles = []string{
	"defaultUrlBlack", "defaultUaBlack", "header", "cookie", "args", "fileExt", "methodWhite",
}

func wafSiteRuleFileValid(f string) bool {
	for _, n := range wafSiteRuleFiles {
		if n == f {
			return true
		}
	}
	return false
}

// wafRuleDirFor 返回规则目录：key 为空 = 全局，否则为站点
func wafRuleDirFor(key string) (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("未找到 1pwaf 配置目录")
	}
	data := wafDataDir(conf)
	if key == "" {
		return filepath.Join(data, "rules"), nil
	}
	if !wafSafeKey(key) {
		return "", fmt.Errorf("站点标识不合法：%s", key)
	}
	return filepath.Join(data, "sites", key, "rules"), nil
}

func wafRulesDirPath() (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("未找到 1pwaf 配置目录")
	}
	return filepath.Join(filepath.Dir(conf), "rules"), nil
}

// wafRuleReadRaw 读原始规则对象数组（保留未知字段，回写时不丢数据）
func wafRuleReadRaw(dir, file string) ([]map[string]interface{}, error) {
	p := filepath.Join(dir, file+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]interface{}{}, nil
		}
		return nil, err
	}
	var f struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("%s.json 解析失败：%v", file, err)
		}
	}
	if f.Rules == nil {
		f.Rules = []map[string]interface{}{}
	}
	return f.Rules, nil
}

func wafRuleWriteRaw(dir, file string, rules []map[string]interface{}) (string, error) {
	p := filepath.Join(dir, file+".json")
	backup, _ := wafBackupFile(p)
	buf, err := json.MarshalIndent(map[string]interface{}{"rules": rules}, "", "  ")
	if err != nil {
		return backup, err
	}
	buf = append(buf, '\n')
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return backup, err
	}
	return backup, os.Rename(tmp, p)
}

// WafRuleMeta GET /api/v2/waf-log/rule/meta?key=
func (b *BaseApi) WafRuleMeta(c *gin.Context) {
	key := c.Query("key")
	dir, err := wafRuleDirFor(key)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	files := make([]gin.H, 0, len(wafRuleFileOrder))
	for _, f := range wafRuleFileOrder {
		if key != "" && !wafSiteRuleFileValid(f) {
			continue
		}
		if key != "" && !wafPathExists(filepath.Join(dir, f+".json")) {
			continue
		}
		rules, _ := wafRuleReadRaw(dir, f)
		on := 0
		for _, r := range rules {
			if wafStr(r["state"]) != "off" {
				on++
			}
		}
		files = append(files, gin.H{
			"file": f, "label": wafRuleFileLabel[f], "count": len(rules), "enabled": on,
		})
	}
	targets := wafRuleTargets
	if key != "" {
		// 站点侧只暴露落到站点规则文件上的匹配位置
		targets = make([]wafRuleTarget, 0, len(wafRuleTargets))
		for _, t := range wafRuleTargets {
			if wafSiteRuleFileValid(t.File) {
				targets = append(targets, t)
			}
		}
	}
	c.JSON(200, gin.H{"code": 200, "message": "", "data": gin.H{
		"ok": true, "dir": dir, "key": key, "files": files, "targets": targets,
	}})
}

// WafRuleAll GET /api/v2/waf-log/rule/all?file=&kw=&onlyOn=1&key=
func (b *BaseApi) WafRuleAll(c *gin.Context) {
	key := c.Query("key")
	dir, err := wafRuleDirFor(key)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	only := c.Query("file")
	kw := strings.ToLower(strings.TrimSpace(c.Query("kw")))
	onlyOn := c.Query("onlyOn") == "1"

	items := make([]gin.H, 0, 128)
	for _, f := range wafRuleFileOrder {
		if only != "" && only != f {
			continue
		}
		if key != "" {
			if !wafSiteRuleFileValid(f) {
				continue
			}
			if !wafPathExists(filepath.Join(dir, f+".json")) {
				continue
			}
		}
		rules, err := wafRuleReadRaw(dir, f)
		if err != nil {
			continue
		}
		for i, r := range rules {
			state := wafStr(r["state"])
			if state == "" {
				state = "on"
			}
			rule := wafStr(r["rule"])
			name := wafStr(r["name"])
			typ := wafStr(r["type"])
			start := wafStr(r["ipStart"])
			end := wafStr(r["ipEnd"])
			if start != "" {
				rule = wafIPv4Display(start, end)
			}
			if onlyOn && state != "on" {
				continue
			}
			if kw != "" {
				hay := strings.ToLower(name + " " + rule + " " + typ + " " + f)
				if !strings.Contains(hay, kw) {
					continue
				}
			}
			item := gin.H{
				"file": f, "label": wafRuleFileLabel[f], "index": i,
				"state": state, "name": name, "rule": rule, "type": typ,
			}
			if start != "" {
				item["start"] = start
				item["end"] = end
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i]["file"].(string) < items[j]["file"].(string)
	})
	c.JSON(200, gin.H{"code": 200, "message": "", "data": gin.H{
		"ok": true, "count": len(items), "items": items,
	}})
}

type wafRuleOpReq struct {
	Op     string `json:"op"` // update | create | delete
	File   string `json:"file"`
	Key    string `json:"key"` // 空=全局，否则站点 key
	Index  int    `json:"index"`
	State  string `json:"state"`
	Name   string `json:"name"`
	Rule   string `json:"rule"`
	Type   string `json:"type"`
	Reload bool   `json:"reload"`
}

// WafRuleOp POST /api/v2/waf-log/rule/op
func (b *BaseApi) WafRuleOp(c *gin.Context) {
	var req wafRuleOpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	if !wafRuleFileValid(req.File) {
		wafBad(c, "不允许操作该规则文件："+req.File)
		return
	}
	if req.Key != "" && !wafSiteRuleFileValid(req.File) {
		wafBad(c, "该规则文件不支持站点级配置："+req.File)
		return
	}
	dir, err := wafRuleDirFor(req.Key)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	if req.Key != "" && !wafPathExists(filepath.Join(dir, req.File+".json")) {
		wafBad(c, "站点下没有该规则文件："+req.File+".json")
		return
	}
	rules, err := wafRuleReadRaw(dir, req.File)
	if err != nil {
		wafBwFail(c, err)
		return
	}

	isIP := req.File == "ipBlack" || req.File == "ipWhite"

	switch req.Op {
	case "update":
		if req.Index < 0 || req.Index >= len(rules) {
			wafBad(c, "下标越界")
			return
		}
		obj := rules[req.Index]
		if req.State != "" {
			obj["state"] = req.State
		}
		if req.Name != "" {
			obj["name"] = req.Name
		}
		if req.Rule != "" {
			if isIP {
				start, end, err := wafIPv4Range(req.Rule)
				if err != nil {
					wafBad(c, err.Error())
					return
				}
				obj["type"] = "ipArr"
				obj["ipStart"], obj["ipEnd"] = start, end
				delete(obj, "rule")
				delete(obj, "ipv4")
				delete(obj, "ipGroup")
			} else {
				obj["rule"] = req.Rule
				if req.Type != "" {
					obj["type"] = req.Type
				}
			}
		}
		rules[req.Index] = obj
	case "create":
		if strings.TrimSpace(req.Rule) == "" {
			wafBad(c, "规则内容不能为空")
			return
		}
		state := req.State
		if state != "on" && state != "off" {
			state = "on"
		}
		obj := map[string]interface{}{"state": state}
		if strings.TrimSpace(req.Name) != "" {
			obj["name"] = strings.TrimSpace(req.Name)
		}
		if isIP {
			start, end, err := wafIPv4Range(req.Rule)
			if err != nil {
				wafBad(c, err.Error())
				return
			}
			obj["type"] = "ipArr"
			obj["ipStart"], obj["ipEnd"] = start, end
		} else {
			obj["rule"] = strings.TrimSpace(req.Rule)
			if req.Type != "" {
				obj["type"] = req.Type
			}
		}
		rules = append(rules, obj)
		req.Index = len(rules) - 1
	case "delete":
		if req.Index < 0 || req.Index >= len(rules) {
			wafBad(c, "下标越界")
			return
		}
		rules = append(rules[:req.Index], rules[req.Index+1:]...)
	default:
		wafBad(c, "未知操作："+req.Op)
		return
	}

	backup, err := wafRuleWriteRaw(dir, req.File, rules)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	res := gin.H{"saved": true, "file": req.File, "key": req.Key, "count": len(rules), "backup": backup}
	if req.Reload {
		output, warns, rerr := wafReloadConf()
		res["reload_output"] = output
		res["reloaded"] = rerr == nil
		res["warnings"] = warns
	}
	c.JSON(200, gin.H{"code": 200, "message": "", "data": res})
}
