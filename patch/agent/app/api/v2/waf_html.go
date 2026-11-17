package v2

// 1Panel v2.x 社区版 WAF「拦截页面」API（补丁文件，新增）
//
// 对应官方 xpack：GET/POST /xpack/waf/html/{update,revert}
//
// 1pwaf 的拦截页面在 data/default/*.html，共 5 个：
//   forbidden.html  命中拦截规则
//   unknown.html    未授权域名
//   cc.html         访问频率限制
//   ip.html         IP 黑名单
//   geo.html        地区限制
// 首次保存自定义内容时会把原文件另存为 <name>.factory，用于「还原默认」。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
)

// 允许改的拦截页面（白名单，防路径穿越）
var wafHtmlPages = map[string]string{
	"forbidden.html": "禁止访问",
	"unknown.html":   "网站不存在",
	"cc.html":        "访问频率限制",
	"ip.html":        "IP 黑名单",
	"geo.html":       "地区限制",
}

const wafHtmlMaxSize = 512 * 1024

func wafHtmlDir() (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("没找到 1pwaf 的 conf 目录")
	}
	dir := filepath.Join(wafDataDir(conf), "default")
	if !wafDirExists(dir) {
		return "", fmt.Errorf("没找到拦截页面目录：%s", dir)
	}
	return dir, nil
}

func wafHtmlPath(name string) (string, error) {
	if _, ok := wafHtmlPages[name]; !ok {
		return "", fmt.Errorf("不支持的拦截页面：%s", name)
	}
	dir, err := wafHtmlDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// WafHtmlList GET /api/v2/waf-log/html/list
func (b *BaseApi) WafHtmlList(c *gin.Context) {
	dir, err := wafHtmlDir()
	if err != nil {
		helper.SuccessWithData(c, gin.H{"ok": false, "hint": err.Error(), "items": []gin.H{}})
		return
	}
	names := make([]string, 0, len(wafHtmlPages))
	for n := range wafHtmlPages {
		names = append(names, n)
	}
	sort.Strings(names)

	items := make([]gin.H, 0, len(names))
	for _, n := range names {
		p := filepath.Join(dir, n)
		st, err := os.Stat(p)
		if err != nil {
			items = append(items, gin.H{"name": n, "label": wafHtmlPages[n], "exists": false})
			continue
		}
		item := gin.H{
			"name": n, "label": wafHtmlPages[n], "exists": true,
			"size": st.Size(), "mtime": st.ModTime().Format("2006-01-02 15:04:05"),
			"modified": wafPathExists(p + ".factory"),
		}
		// 有 .factory 说明被改过，对比一下当前内容是否与出厂一致
		if item["modified"] == true {
			cur, e1 := os.ReadFile(p)
			org, e2 := os.ReadFile(p + ".factory")
			if e1 == nil && e2 == nil && string(cur) == string(org) {
				item["modified"] = false
			}
		}
		items = append(items, item)
	}
	helper.SuccessWithData(c, gin.H{"ok": true, "dir": dir, "items": items})
}

// WafHtmlGet GET /api/v2/waf-log/html/get?name=forbidden.html
func (b *BaseApi) WafHtmlGet(c *gin.Context) {
	name := c.Query("name")
	p, err := wafHtmlPath(name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, gin.H{"name": name, "label": wafHtmlPages[name], "content": string(raw), "size": len(raw)})
}

type wafHtmlSaveReq struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Reload  bool   `json:"reload"`
}

// WafHtmlSave POST /api/v2/waf-log/html/save
func (b *BaseApi) WafHtmlSave(c *gin.Context) {
	var req wafHtmlSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	p, err := wafHtmlPath(req.Name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	if len(req.Content) > wafHtmlMaxSize {
		wafBad(c, "页面内容不能超过 512KB")
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		wafBad(c, "页面内容不能为空")
		return
	}

	// 第一次改的时候留一份出厂副本
	factory := p + ".factory"
	if !wafPathExists(factory) {
		if raw, err := os.ReadFile(p); err == nil {
			if err := os.WriteFile(factory, raw, 0o644); err != nil {
				helper.InternalServer(c, err)
				return
			}
		}
	}
	backup, _ := wafBackupFile(p)

	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(req.Content), 0o644); err != nil {
		helper.InternalServer(c, err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		helper.InternalServer(c, err)
		return
	}

	res := gin.H{"saved": true, "name": req.Name, "backup": backup, "reloaded": false}
	if req.Reload {
		out, warns, err := wafReloadConf()
		res["reload_output"] = out
		res["warnings"] = warns
		if err != nil {
			res["reload_error"] = err.Error()
		} else {
			res["reloaded"] = true
		}
	}
	helper.SuccessWithData(c, res)
}

// WafHtmlRevert POST /api/v2/waf-log/html/revert {name}
func (b *BaseApi) WafHtmlRevert(c *gin.Context) {
	var req struct {
		Name   string `json:"name"`
		Reload bool   `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	p, err := wafHtmlPath(req.Name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	factory := p + ".factory"
	raw, err := os.ReadFile(factory)
	if err != nil {
		wafBad(c, "没有找到出厂副本，无法还原")
		return
	}
	backup, _ := wafBackupFile(p)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		helper.InternalServer(c, err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		helper.InternalServer(c, err)
		return
	}
	res := gin.H{"saved": true, "name": req.Name, "backup": backup, "reloaded": false}
	if req.Reload {
		out, warns, err := wafReloadConf()
		res["reload_output"] = out
		res["warnings"] = warns
		if err != nil {
			res["reload_error"] = err.Error()
		} else {
			res["reloaded"] = true
		}
	}
	helper.SuccessWithData(c, res)
}
