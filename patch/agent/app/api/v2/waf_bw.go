package v2

// 1Panel v2.x 社区版 WAF「黑白名单」API（补丁文件，新增）
//
// 名单数据全部在 data/rules/*.json，结构与内置规则一致：{"rules":[ {...} ]}
// 但 IP 名单的条目不是普通规则对象，反编译 lib.lua 的 IP 匹配分支后确认，
// 合法的 type 只有三种：
//   ipv4    —— {type:"ipv4", ipv4:<uint32>}            实测会让整条链路 500，不用
//   ipArr   —— {type:"ipArr", ipStart:"a.b.c.d", ipEnd:"a.b.c.d"}    ✅ 实际使用
//   ipGroup —— {type:"ipGroup", ipGroup:"<分组名>"}      需要 data/rules/ip_group/*.json
// URL 名单：{type:"dirFilter", rule:"<正则/路径>"}
// UA  名单：{type:"scannerFilter", rule:"<正则>"}
//
// 实测结论（2026-11-16，在 测试站点:880 上）：
//   ipBlack  ipStart=127.0.0.50 ipEnd=127.0.0.60 → 从 .55 访问 403，.70 访问 200
//   urlBlack rule="/blockme" type=dirFilter      → /blockme 403，/ 200
//   uaBlack  rule="BadBot"  type=scannerFilter   → UA=BadBot 403
//   ipWhite 与 ipBlack 同时命中同一 IP             → 200（白名单优先）

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// wafBwKinds 允许操作的白/黑名单文件
var wafBwKinds = map[string]string{
	"ipBlack":  "ip",
	"ipWhite":  "ip",
	"urlBlack": "url",
	"urlWhite": "url",
	"uaBlack":  "ua",
	"uaWhite":  "ua",
}

// wafBwFail 统一 500 响应（不依赖 helper 包的内部实现）
func wafBwFail(c *gin.Context, err error) {
	c.JSON(500, gin.H{"code": 500, "message": err.Error(), "data": nil})
}

func wafBwDir() (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("未找到 1pwaf 配置目录")
	}
	return filepath.Join(filepath.Dir(conf), "rules"), nil
}

// wafBwEntry 对外统一的条目模型
type wafBwEntry struct {
	State string `json:"state"`           // on / off
	Name  string `json:"name,omitempty"`  // 备注
	Rule  string `json:"rule,omitempty"`  // url/ua 的值，或 ip 的展示值（CIDR / a-b）
	Type  string `json:"type,omitempty"`  // 原始 type
	Start string `json:"start,omitempty"` // ip 起始
	End   string `json:"end,omitempty"`   // ip 结束
}

// ---------- IP 工具 ----------

func wafIPv4ToInt(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

func wafIntToIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// wafIPv4Range 把 "1.2.3.4" / "1.2.3.0/24" / "1.2.3.4-1.2.3.20" 统一成起止 IP
func wafIPv4Range(val string) (string, string, error) {
	v := strings.TrimSpace(val)
	if v == "" {
		return "", "", fmt.Errorf("IP 不能为空")
	}
	if strings.Contains(v, "/") {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil || ipnet.IP.To4() == nil {
			return "", "", fmt.Errorf("CIDR 格式不对：%s", v)
		}
		start, ok1 := wafIPv4ToInt(ipnet.IP.String())
		ones, bits := ipnet.Mask.Size()
		if !ok1 || bits != 32 {
			return "", "", fmt.Errorf("CIDR 格式不对：%s", v)
		}
		size := uint32(1) << uint(bits-ones)
		return wafIntToIPv4(start), wafIntToIPv4(start + size - 1), nil
	}
	if i := strings.Index(v, "-"); i > 0 {
		s, e := strings.TrimSpace(v[:i]), strings.TrimSpace(v[i+1:])
		si, ok1 := wafIPv4ToInt(s)
		ei, ok2 := wafIPv4ToInt(e)
		if !ok1 || !ok2 {
			return "", "", fmt.Errorf("IP 区间格式不对：%s", v)
		}
		if si > ei {
			si, ei = ei, si
		}
		return wafIntToIPv4(si), wafIntToIPv4(ei), nil
	}
	si, ok := wafIPv4ToInt(v)
	if !ok {
		return "", "", fmt.Errorf("IP 格式不对：%s", v)
	}
	return wafIntToIPv4(si), wafIntToIPv4(si), nil
}

// wafIPv4Display 起止 IP → 展示值（连续网段尝试还原成 CIDR）
func wafIPv4Display(start, end string) string {
	si, ok1 := wafIPv4ToInt(start)
	ei, ok2 := wafIPv4ToInt(end)
	if !ok1 || !ok2 {
		return start + "-" + end
	}
	if si == ei {
		return start
	}
	size := ei - si + 1
	// 仅当 size 是 2 的幂且起点对齐时才可能是合法 CIDR
	if size&(size-1) == 0 && si%size == 0 {
		bits := 32
		for n := size; n > 1; n >>= 1 {
			bits--
		}
		if ipnet := (&net.IPNet{IP: net.IPv4(byte(si>>24), byte(si>>16), byte(si>>8), byte(si)), Mask: net.CIDRMask(bits, 32)}); ipnet.IP != nil {
			return ipnet.String()
		}
	}
	return start + "-" + end
}

// ---------- 读写名单文件 ----------

func wafBwPath(kind string) (string, error) {
	dir, err := wafBwDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, kind+".json"), nil
}

// wafBwRead 读名单并归一化成统一的条目
func wafBwRead(kind string) ([]wafBwEntry, error) {
	p, err := wafBwPath(kind)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []wafBwEntry{}, nil
		}
		return nil, err
	}
	var file struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &file); err != nil {
			return nil, fmt.Errorf("%s.json 解析失败：%v", kind, err)
		}
	}
	out := make([]wafBwEntry, 0, len(file.Rules))
	for _, r := range file.Rules {
		e := wafBwEntry{
			State: wafStr(r["state"]),
			Name:  wafStr(r["name"]),
			Rule:  wafStr(r["rule"]),
			Type:  wafStr(r["type"]),
		}
		if e.State == "" {
			e.State = "on"
		}
		if strings.HasPrefix(wafBwKinds[kind], "ip") {
			// 兼容历史条目：ipStart/ipEnd 或 ipv4 / ipGroup
			e.Start = wafStr(r["ipStart"])
			e.End = wafStr(r["ipEnd"])
			if e.Start == "" && r["ipv4"] != nil {
				switch v := r["ipv4"].(type) {
				case float64:
					e.Start = wafIntToIPv4(uint32(v))
				case string:
					e.Start = v
				}
				e.End = e.Start
			}
			if e.Start == "" && wafStr(r["ipGroup"]) != "" {
				e.Start = wafStr(r["ipGroup"])
				e.End = e.Start
				e.Type = "ipGroup"
			}
			if e.Start != "" && e.End == "" {
				e.End = e.Start
			}
			if e.Start != "" {
				e.Rule = wafIPv4Display(e.Start, e.End)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// wafBwMarshal 把统一条目转成 Lua 能识别的原样对象
func wafBwMarshal(kind string, entries []wafBwEntry) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		state := e.State
		if state != "on" && state != "off" {
			state = "on"
		}
		name := strings.TrimSpace(e.Name)
		item := map[string]interface{}{"state": state}
		if name != "" {
			item["name"] = name
		}
		switch wafBwKinds[kind] {
		case "ip":
			start, end := strings.TrimSpace(e.Start), strings.TrimSpace(e.End)
			if start == "" {
				start, end, _ = wafIPv4Range(e.Rule)
			}
			if end == "" {
				end = start
			}
			if e.Type == "ipGroup" {
				item["type"] = "ipGroup"
				item["ipGroup"] = start
			} else {
				item["type"] = "ipArr"
				item["ipStart"] = start
				item["ipEnd"] = end
			}
		case "url":
			item["type"] = "dirFilter"
			item["rule"] = strings.TrimSpace(e.Rule)
		case "ua":
			item["type"] = "scannerFilter"
			item["rule"] = strings.TrimSpace(e.Rule)
		}
		out = append(out, item)
	}
	return out
}

// ---------- 接口 ----------

// WafBwGet GET /api/v2/waf-log/bw/get?kind=ipBlack
func (b *BaseApi) WafBwGet(c *gin.Context) {
	kind := c.Query("kind")
	if _, ok := wafBwKinds[kind]; !ok {
		wafBad(c, "未知名单类型："+kind)
		return
	}
	entries, err := wafBwRead(kind)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	path, _ := wafBwPath(kind)
	c.JSON(200, gin.H{"code": 200, "message": "", "data": gin.H{
		"ok":      true,
		"kind":    kind,
		"path":    path,
		"count":   len(entries),
		"entries": entries,
	}})
}

type wafBwSaveReq struct {
	Kind    string       `json:"kind"`
	Entries []wafBwEntry `json:"entries"`
	Reload  bool         `json:"reload"`
}

// WafBwSave POST /api/v2/waf-log/bw/save
func (b *BaseApi) WafBwSave(c *gin.Context) {
	var req wafBwSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	if _, ok := wafBwKinds[req.Kind]; !ok {
		wafBad(c, "未知名单类型："+req.Kind)
		return
	}
	// 校验 IP 条目
	if wafBwKinds[req.Kind] == "ip" {
		for i := range req.Entries {
			e := &req.Entries[i]
			if e.Type == "ipGroup" {
				if strings.TrimSpace(e.Start) == "" && strings.TrimSpace(e.Rule) == "" {
					wafBad(c, "IP 分组名不能为空")
					return
				}
				continue
			}
			if e.Start != "" {
				if _, _, err := wafIPv4Range(e.Start); err != nil {
					wafBad(c, err.Error())
					return
				}
				if e.End != "" {
					if _, _, err := wafIPv4Range(e.End); err != nil {
						wafBad(c, err.Error())
						return
					}
				}
				continue
			}
			s, en, err := wafIPv4Range(e.Rule)
			if err != nil {
				wafBad(c, err.Error())
				return
			}
			e.Start, e.End = s, en
			e.Rule = wafIPv4Display(s, en)
		}
	} else {
		for _, e := range req.Entries {
			if strings.TrimSpace(e.Rule) == "" {
				wafBad(c, "规则内容不能为空")
				return
			}
		}
	}

	p, err := wafBwPath(req.Kind)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	backup, _ := wafBackupFile(p)

	body := map[string]interface{}{"rules": wafBwMarshal(req.Kind, req.Entries)}
	buf, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		wafBwFail(c, err)
		return
	}
	buf = append(buf, '\n')
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		wafBwFail(c, err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		wafBwFail(c, err)
		return
	}

	res := gin.H{"saved": true, "path": p, "count": len(req.Entries), "backup": backup}
	warns := []string{}
	if req.Reload {
		output, w, err := wafReloadConf()
		res["reload_output"] = output
		if len(w) > 0 {
			warns = append(warns, w...)
		}
		if err != nil {
			res["reloaded"] = false
			warns = append(warns, "reload 失败："+err.Error())
		} else {
			res["reloaded"] = true
		}
	}
	res["warnings"] = warns
	c.JSON(200, gin.H{"code": 200, "message": "", "data": res})
}

// WafBwToggle POST /api/v2/waf-log/bw/toggle {kind,index,state,reload}
type wafBwToggleReq struct {
	Kind   string `json:"kind"`
	Index  int    `json:"index"`
	State  string `json:"state"`
	Reload bool   `json:"reload"`
}

func (b *BaseApi) WafBwToggle(c *gin.Context) {
	var req wafBwToggleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	if _, ok := wafBwKinds[req.Kind]; !ok {
		wafBad(c, "未知名单类型："+req.Kind)
		return
	}
	entries, err := wafBwRead(req.Kind)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	if req.Index < 0 || req.Index >= len(entries) {
		wafBad(c, "下标越界")
		return
	}
	entries[req.Index].State = req.State
	p, _ := wafBwPath(req.Kind)
	backup, _ := wafBackupFile(p)
	body := map[string]interface{}{"rules": wafBwMarshal(req.Kind, entries)}
	buf, _ := json.MarshalIndent(body, "", "  ")
	buf = append(buf, '\n')
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		wafBwFail(c, err)
		return
	}
	res := gin.H{"saved": true, "path": p, "backup": backup}
	if req.Reload {
		output, _, rerr := wafReloadConf()
		res["reload_output"] = output
		res["reloaded"] = rerr == nil
	}
	c.JSON(200, gin.H{"code": 200, "message": "", "data": res})
}

// WafBwImport POST /api/v2/waf-log/bw/import {kind,text,state,reload}
// text 每行一条：值[ tab 或 空格 或 | 备注]
type wafBwImportReq struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	State  string `json:"state"`
	Reload bool   `json:"reload"`
}

func (b *BaseApi) WafBwImport(c *gin.Context) {
	var req wafBwImportReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	kindKind, ok := wafBwKinds[req.Kind]
	if !ok {
		wafBad(c, "未知名单类型："+req.Kind)
		return
	}
	entries, err := wafBwRead(req.Kind)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	state := req.State
	if state != "on" && state != "off" {
		state = "on"
	}
	exist := map[string]bool{}
	for _, e := range entries {
		exist[e.Start+"|"+e.Rule] = true
	}
	added, skipped, failed := 0, 0, []string{}
	lines := strings.Split(strings.ReplaceAll(req.Text, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		val, remark := line, ""
		for _, sep := range []string{"\t", "|", " "} {
			if i := strings.Index(line, sep); i > 0 {
				val = strings.TrimSpace(line[:i])
				remark = strings.TrimSpace(line[i+1:])
				break
			}
		}
		e := wafBwEntry{State: state, Name: remark, Rule: val}
		if kindKind == "ip" {
			s, en, err := wafIPv4Range(val)
			if err != nil {
				failed = append(failed, val)
				continue
			}
			e.Start, e.End = s, en
			if exist[s+"|"+wafIPv4Display(s, en)] {
				skipped++
				continue
			}
			exist[s+"|"+wafIPv4Display(s, en)] = true
		} else if exist["|"+val] {
			skipped++
			continue
		} else {
			exist["|"+val] = true
		}
		entries = append(entries, e)
		added++
	}

	p, _ := wafBwPath(req.Kind)
	backup, _ := wafBackupFile(p)
	body := map[string]interface{}{"rules": wafBwMarshal(req.Kind, entries)}
	buf, _ := json.MarshalIndent(body, "", "  ")
	buf = append(buf, '\n')
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		wafBwFail(c, err)
		return
	}
	res := gin.H{
		"saved": true, "added": added, "skipped": skipped,
		"failed": failed, "total": len(entries), "backup": backup, "path": p,
	}
	if req.Reload {
		output, _, rerr := wafReloadConf()
		res["reload_output"] = output
		res["reloaded"] = rerr == nil
	}
	c.JSON(200, gin.H{"code": 200, "message": "", "data": res})
}

// WafBwSummary GET /api/v2/waf-log/bw/summary 六种名单的条数与开关
func (b *BaseApi) WafBwSummary(c *gin.Context) {
	conf := wafConfDir()
	global, _, _ := wafReadJSONMap(filepath.Join(conf, "global.json"))
	kinds := make([]string, 0, len(wafBwKinds))
	for k := range wafBwKinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	items := make([]gin.H, 0, len(kinds))
	for _, k := range kinds {
		n := 0
		if es, err := wafBwRead(k); err == nil {
			n = len(es)
		}
		state, action, code := "off", "", 0
		if g, ok := global[k].(map[string]interface{}); ok {
			state = wafStr(g["state"])
			action = wafStr(g["action"])
			if v, ok := g["code"].(float64); ok {
				code = int(v)
			}
		}
		items = append(items, gin.H{
			"kind": k, "group": wafBwKinds[k], "count": n,
			"state": state, "action": action, "code": code,
		})
	}
	c.JSON(200, gin.H{"code": 200, "message": "", "data": gin.H{
		"ok": true, "items": items, "conf_dir": conf, "ts": time.Now().Unix(),
	}})
}
