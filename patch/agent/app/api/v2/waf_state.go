package v2

// 1Panel v2.x 社区版 WAF「模块开关」API（补丁文件，新增）
//
// 对应官方 xpack 的两个接口：
//   POST /xpack/waf/config/global/state   {scope,state}            改全局默认
//   POST /xpack/waf/config/website/state  {websiteID,scope,state}  改单站
//
// 官方页面交互是「开关一拨就立即生效」，而不是整页保存，
// 所以这里单独做一个只改单个模块 state（可选 mode）的接口，
// 避免前端每次拨开关都要把整份 global.json 回写一遍。

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
)

// 全局配置里允许单独拨开关的模块
var wafGlobalScopeKeys = map[string]bool{
	"waf": true, "sql": true, "xss": true, "strict": true,
	"args": true, "cookie": true, "header": true,
	"methodWhite": true, "defaultUaBlack": true, "defaultUrlBlack": true, "defaultIpBlack": true,
	"ipBlack": true, "ipWhite": true, "urlBlack": true, "urlWhite": true, "uaBlack": true, "uaWhite": true,
	"unknownWebsite": true, "allowSpider": true, "vuln": true,
	"fileExt": true, "geoRestrict": true, "cdn": true, "app": true,
	"cc": true, "urlcc": true, "attackCount": true, "notFoundCount": true,
	"log": true,
}

// 站点级 config.json 只有这 15 个模块
var wafSiteScopeKeys = map[string]bool{
	"waf": true, "sql": true, "xss": true, "strict": true,
	"args": true, "cookie": true, "header": true,
	"methodWhite": true, "defaultUaBlack": true, "defaultUrlBlack": true,
	"fileExt": true, "geoRestrict": true, "cdn": true, "cc": true, "app": true,
}

type wafStateReq struct {
	Key    string `json:"key"`   // 站点标识，空=全局
	Scope  string `json:"scope"` // 模块名，如 waf / sql / cc
	State  string `json:"state"` // on / off
	Mode   string `json:"mode"`  // 仅 waf 用：protection / observation
	Reload *bool  `json:"reload"`
}

// WafState POST /api/v2/waf-log/state
func (b *BaseApi) WafState(c *gin.Context) {
	var req wafStateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	if req.Scope == "" {
		wafBad(c, "缺少 scope")
		return
	}
	if req.State != "" && req.State != "on" && req.State != "off" {
		wafBad(c, "state 只能是 on / off")
		return
	}

	conf := wafConfDir()
	if conf == "" {
		helper.InternalServer(c, fmt.Errorf("没找到 1pwaf 的 conf 目录"))
		return
	}

	var path string
	if req.Key == "" {
		if !wafGlobalScopeKeys[req.Scope] {
			wafBad(c, "全局配置不支持该模块："+req.Scope)
			return
		}
		path = filepath.Join(conf, "global.json")
	} else {
		if !wafSafeKey(req.Key) {
			wafBad(c, "站点标识不合法")
			return
		}
		if !wafSiteScopeKeys[req.Scope] {
			wafBad(c, "站点配置不支持该模块（属于全局）:"+req.Scope)
			return
		}
		path = filepath.Join(wafSiteDir(wafDataDir(conf), req.Key), "config.json")
	}

	if !wafPathExists(path) {
		helper.InternalServer(c, fmt.Errorf("配置文件不存在：%s", path))
		return
	}
	m, _, err := wafReadJSONMap(path)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}

	// 取模块对象；不存在则按站点/全局分别建一个最小骨架
	var mod map[string]interface{}
	if v, ok := m[req.Scope]; ok {
		if obj, isMap := v.(map[string]interface{}); isMap {
			mod = obj
		}
	}
	if mod == nil {
		mod = map[string]interface{}{"type": req.Scope}
		if req.Scope == "waf" {
			mod = map[string]interface{}{}
		}
	}
	if req.State != "" {
		mod["state"] = req.State
	}
	if req.Mode != "" {
		if req.Scope != "waf" {
			wafBad(c, "只有 waf 模块有 mode")
			return
		}
		if req.Mode != "protection" && req.Mode != "observation" {
			wafBad(c, "mode 只能是 protection / observation")
			return
		}
		mod["mode"] = req.Mode
	}
	if _, ok := mod["state"]; !ok {
		wafBad(c, "缺少 state")
		return
	}
	m[req.Scope] = mod

	if _, err := wafBackupFile(path); err != nil && !os.IsNotExist(err) {
		// 备份失败不阻断写入
		_ = err
	}
	if err := wafWriteJSONMap(path, m); err != nil {
		helper.InternalServer(c, err)
		return
	}

	res := gin.H{"saved": true, "key": req.Key, "scope": req.Scope, "state": mod["state"], "reloaded": false}
	doReload := req.Reload == nil || *req.Reload
	if doReload {
		out, warns, rerr := wafReloadConf()
		res["reload_output"] = out
		res["warnings"] = warns
		if rerr != nil {
			res["reload_error"] = rerr.Error()
		} else {
			res["reloaded"] = true
		}
	}
	helper.SuccessWithData(c, res)
}
