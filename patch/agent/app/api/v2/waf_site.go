package v2

// 1Panel v2.x 社区版 WAF「网站设置」API（补丁文件，新增）
//
// 官方 xpack 的 WAF 用三处数据描述一个站点：
//   data/conf/sites.json               站点索引：[{"key","domains","host"}]
//   data/sites/<key>/config.json       站点级开关（15 项，等同 siteConfig.json 的子集）
//   data/sites/<key>/rules/*.json      站点级规则库 {"rules":[{"state","name","rule","type"}]}
//
// 1Panel 创建网站时会自动把站点写进这三处，本文件只负责读/改，不负责建站。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
)

// 站点 key 只允许常规域名/站点名，防路径穿越
var wafSiteKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$`)

func wafSafeKey(k string) bool {
	if k == "" || !wafSiteKeyRe.MatchString(k) || strings.Contains(k, "..") {
		return false
	}
	return true
}

// wafBad helper.BadRequest 需要 error，这里统一包一层
func wafBad(c *gin.Context, msg string) { helper.BadRequest(c, fmt.Errorf("%s", msg)) }

type wafSiteEntry struct {
	Key     string   `json:"key"`
	Domains []string `json:"domains"`
	Host    []string `json:"host"`
}

// wafReadSitesIndex 读 conf/sites.json，兼容数组与 {"websites":[...]} 两种写法
func wafReadSitesIndex(conf string) []wafSiteEntry {
	p := filepath.Join(conf, "sites.json")
	raw, err := os.ReadFile(p)
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var arr []wafSiteEntry
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var wrap struct {
		Websites []wafSiteEntry `json:"websites"`
	}
	if json.Unmarshal(raw, &wrap) == nil {
		return wrap.Websites
	}
	return nil
}

func wafSiteDir(dataDir, key string) string {
	return filepath.Join(dataDir, "sites", key)
}

// wafSiteSummary 汇总站点级规则库
func wafSiteSummary(dir string) (int, int) {
	rulesDir := filepath.Join(dir, "rules")
	ents, err := os.ReadDir(rulesDir)
	if err != nil {
		return 0, 0
	}
	total, enabled := 0, 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(rulesDir, e.Name()))
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		list, _ := m["rules"].([]interface{})
		for _, it := range list {
			obj, _ := it.(map[string]interface{})
			total++
			if st, _ := obj["state"].(string); st == "on" {
				enabled++
			}
		}
	}
	return total, enabled
}

// WafSiteList 站点列表：sites.json + 每个站点目录的 config.json
func (b *BaseApi) WafSiteList(c *gin.Context) {
	conf := wafConfDir()
	if conf == "" {
		helper.SuccessWithData(c, gin.H{"ok": false, "hint": "未找到 1pwaf 配置目录", "sites": []gin.H{}})
		return
	}
	dataDir := wafDataDir(conf)
	index := wafReadSitesIndex(conf)

	// 以目录为准做并集：sites.json 里没有但目录存在的也列出来
	seen := make(map[string]bool, len(index))
	out := make([]gin.H, 0, len(index)+2)
	add := func(key string, ent *wafSiteEntry) {
		if !wafSafeKey(key) || seen[key] {
			return
		}
		seen[key] = true
		dir := wafSiteDir(dataDir, key)
		item := gin.H{
			"key": key, "dir": dir, "exists": wafPathExists(filepath.Join(dir, "config.json")),
			"waf_state": "off", "waf_mode": "protection", "strict_state": "off", "cc_state": "off",
			"total_rules": 0, "enabled_rules": 0,
		}
		if ent != nil {
			item["domains"] = ent.Domains
			item["host"] = ent.Host
		}
		if raw, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
			var cfg map[string]interface{}
			if json.Unmarshal(raw, &cfg) == nil {
				if w, ok := cfg["waf"].(map[string]interface{}); ok {
					if st, _ := w["state"].(string); st != "" {
						item["waf_state"] = st
					}
					if md, _ := w["mode"].(string); md != "" {
						item["waf_mode"] = md
					}
				}
				if s2, ok := cfg["strict"].(map[string]interface{}); ok {
					if st, _ := s2["state"].(string); st != "" {
						item["strict_state"] = st
					}
				}
				if c2, ok := cfg["cc"].(map[string]interface{}); ok {
					if st, _ := c2["state"].(string); st != "" {
						item["cc_state"] = st
					}
				}
			}
		}
		t, e := wafSiteSummary(dir)
		item["total_rules"], item["enabled_rules"] = t, e
		out = append(out, item)
	}

	for i := range index {
		add(index[i].Key, &index[i])
	}
	if ents, err := os.ReadDir(filepath.Join(dataDir, "sites")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				add(e.Name(), nil)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["key"].(string) < out[j]["key"].(string)
	})
	// 站点「检测强度」依赖全局严格模式，列表页需要知道全局是否开启
	globalStrict := "off"
	if gm, _, err := wafReadJSONMap(filepath.Join(conf, "global.json")); err == nil {
		if s2, ok := gm["strict"].(map[string]interface{}); ok {
			if st, _ := s2["state"].(string); st != "" {
				globalStrict = st
			}
		}
	}
	helper.SuccessWithData(c, gin.H{
		"ok": true, "conf_dir": conf, "data_dir": dataDir, "global_strict": globalStrict,
		"count": len(out), "sites": out,
	})
}

// WafSiteConfig 读单个站点的 config.json
func (b *BaseApi) WafSiteConfig(c *gin.Context) {
	key := c.Query("key")
	if !wafSafeKey(key) {
		wafBad(c, "站点标识不合法")
		return
	}
	conf := wafConfDir()
	if conf == "" {
		helper.SuccessWithData(c, gin.H{"ok": false, "hint": "未找到 1pwaf 配置目录"})
		return
	}
	dataDir := wafDataDir(conf)
	dir := wafSiteDir(dataDir, key)
	cfgPath := filepath.Join(dir, "config.json")
	if !wafPathExists(cfgPath) {
		helper.SuccessWithData(c, gin.H{"ok": false, "hint": "站点配置不存在：" + cfgPath, "key": key})
		return
	}
	cfg, _, err := wafReadJSONMap(cfgPath)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	// 附带规则库概览
	rules := make([]gin.H, 0, 16)
	if ents, err := os.ReadDir(filepath.Join(dir, "rules")); err == nil {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			raw, err := os.ReadFile(filepath.Join(dir, "rules", n))
			if err != nil {
				continue
			}
			var m map[string]interface{}
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			list, _ := m["rules"].([]interface{})
			on := 0
			for _, it := range list {
				if obj, ok := it.(map[string]interface{}); ok {
					if st, _ := obj["state"].(string); st == "on" {
						on++
					}
				}
			}
			rules = append(rules, gin.H{
				"file": n, "total": len(list), "enabled": on,
				"size": len(raw),
			})
		}
	}
	helper.SuccessWithData(c, gin.H{
		"ok": true, "key": key, "dir": dir, "config": cfg,
		"rules": rules, "warnings": []string{},
	})
}

type wafSiteConfigReq struct {
	Key    string                 `json:"key"`
	Config map[string]interface{} `json:"config"`
	Reload bool                   `json:"reload"`
}

// WafSiteConfigSave 写站点 config.json（备份 + 可选 reload）
func (b *BaseApi) WafSiteConfigSave(c *gin.Context) {
	var req wafSiteConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	if !wafSafeKey(req.Key) {
		wafBad(c, "站点标识不合法")
		return
	}
	conf := wafConfDir()
	if conf == "" {
		helper.InternalServer(c, fmt.Errorf("未找到 1pwaf 配置目录"))
		return
	}
	dataDir := wafDataDir(conf)
	cfgPath := filepath.Join(wafSiteDir(dataDir, req.Key), "config.json")
	if !wafPathExists(cfgPath) {
		wafBad(c, "站点配置不存在："+cfgPath)
		return
	}
	warns := wafValidateGlobal(req.Config)
	if err := wafWriteJSONMap(cfgPath, req.Config); err != nil {
		helper.InternalServer(c, err)
		return
	}
	backup, _ := wafBackupFile(cfgPath)
	res := gin.H{"saved": true, "path": cfgPath, "warnings": warns}
	if backup != "" {
		res["backup"] = backup
	}
	if req.Reload {
		out, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = out
		res["warnings"] = append(warns, w...)
		if err != nil {
			helper.SuccessWithData(c, res)
			return
		}
		time.Sleep(900 * time.Millisecond)
	}
	helper.SuccessWithData(c, res)
}

// WafSiteRuleGet 读站点某个规则文件全文
func (b *BaseApi) WafSiteRuleGet(c *gin.Context) {
	key := c.Query("key")
	file := c.Query("file")
	if !wafSafeKey(key) || !wafSafeKey(strings.TrimSuffix(file, ".json")) || !strings.HasSuffix(file, ".json") {
		wafBad(c, "参数不合法")
		return
	}
	conf := wafConfDir()
	if conf == "" {
		helper.InternalServer(c, fmt.Errorf("未找到 1pwaf 配置目录"))
		return
	}
	p := filepath.Join(wafSiteDir(wafDataDir(conf), key), "rules", file)
	raw, err := os.ReadFile(p)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, gin.H{"ok": true, "key": key, "file": file, "content": string(raw)})
}

type wafSiteRuleReq struct {
	Key     string `json:"key"`
	File    string `json:"file"`
	Content string `json:"content"`
	Reload  bool   `json:"reload"`
}

// WafSiteRuleSave 写站点规则文件（必须能解析为 {"rules":[...]}）
func (b *BaseApi) WafSiteRuleSave(c *gin.Context) {
	var req wafSiteRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	if !wafSafeKey(req.Key) || !strings.HasSuffix(req.File, ".json") ||
		!wafSafeKey(strings.TrimSuffix(req.File, ".json")) {
		wafBad(c, "参数不合法")
		return
	}
	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(req.Content), &probe); err != nil {
		wafBad(c, "JSON 解析失败："+err.Error())
		return
	}
	if _, ok := probe["rules"]; !ok {
		wafBad(c, `规则文件必须是 {"rules": [...]} 结构`)
		return
	}
	conf := wafConfDir()
	if conf == "" {
		helper.InternalServer(c, fmt.Errorf("未找到 1pwaf 配置目录"))
		return
	}
	p := filepath.Join(wafSiteDir(wafDataDir(conf), req.Key), "rules", req.File)
	if !wafPathExists(p) {
		wafBad(c, "规则文件不存在："+p)
		return
	}
	backup, _ := wafBackupFile(p)
	if err := os.WriteFile(p+".tmp", []byte(req.Content), 0644); err != nil {
		helper.InternalServer(c, err)
		return
	}
	if err := os.Rename(p+".tmp", p); err != nil {
		helper.InternalServer(c, err)
		return
	}
	res := gin.H{"saved": true, "path": p}
	if backup != "" {
		res["backup"] = backup
	}
	if req.Reload {
		out, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = out
		res["warnings"] = w
		if err == nil {
			time.Sleep(900 * time.Millisecond)
		}
	}
	helper.SuccessWithData(c, res)
}
