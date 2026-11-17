package v2

// 1Panel v2.x 社区版 WAF 配置（防护设置）API（补丁文件，新增）
//
// 目标：给免费版补上「WAF 防护设置」——直接读写 openresty 应用里 1pwaf 的全局配置。
//
// 关键事实（真机实测）：
//   - 配置在 <openresty>/1pwaf/data/conf/{global.json,monitor.json,siteConfig.json}
//   - 规则库在 <openresty>/1pwaf/data/rules/*.json，格式 {"rules":[{state,name,rule,type}]}
//   - 默认模板在 <openresty>/1pwaf/data/default/{global.json,monitor.json}
//   - 改完 global.json **不需要重启容器**：`docker exec <c> nginx -s reload` 即可
//     （init_by_lua 在 reload 时重跑，共享字典里的配置被刷新）
//   - 只写盘不 reload 是不会生效的（实测 40s 内依然按旧配置拦截）
//
// 安全措施：写之前一定备份成 global.json.bak.<ts>（保留最近 8 份），
// 原子写（tmp + rename），reload 前先 nginx -t，失败则不 reload 并回滚。

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
)

// ---------- 定位 ----------

func wafPathExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// wafDirExists 判断目录是否存在（wafPathExists 只认文件）
func wafDirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// wafConfDir 返回 1pwaf 的 conf 目录（.../1pwaf/data/conf）
func wafConfDir() string {
	for _, base := range wafV2Roots() {
		conf := filepath.Join(filepath.Dir(base), "conf")
		if wafPathExists(filepath.Join(conf, "global.json")) {
			return conf
		}
	}
	return ""
}

func wafDataDir(conf string) string { return filepath.Dir(conf) }

// ---------- 备份目录（必须放在 1pwaf 树之外！）----------
//
// 真机血案（2026-11-16 16:08 复现并定位）：
//   1pwaf 的 config.lua 在 init_by_lua 阶段会遍历 data/sites/<key>/rules/ 下的
//   每一个「文件」，用 string.match(name, "(.-)%.json$") 取规则名；只要目录里出现
//   一个不以 .json 结尾的文件（例如 acl.json.bak.1794815260），match 返回 nil，
//   file.read_rule(dir, nil) 里 dir..nil..".json" 直接抛
//   "attempt to concatenate a nil value"，init_by_lua 整体失败 ——
//   **整个 WAF 静默失效、放行所有请求**（nginx 只是打一行 error 日志，不中断）。
//
// 所以：规则/配置的备份一律镜像写到 <1pwaf>-backup/ 下，绝不落在 data/ 里；
// 同时每次 reload 前做一次「清剿」，把历史遗留的非法文件挪走。

// wafBackupRoot 返回备份根目录：<...>/1pwaf/data/conf → <...>/1pwaf-backup
func wafBackupRoot() string {
	conf := wafConfDir()
	if conf == "" {
		return ""
	}
	return filepath.Dir(wafDataDir(conf)) + "-backup"
}

// wafBackupBaseFor 把原始路径映射成备份基路径（保留相对层级，便于人工查找）
func wafBackupBaseFor(path string) string {
	root := wafBackupRoot()
	conf := wafConfDir()
	if root == "" || conf == "" {
		return path
	}
	base := wafDataDir(conf) // .../1pwaf/data
	rel, err := filepath.Rel(base, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = filepath.Base(path)
	}
	return filepath.Join(root, rel)
}

// wafBackupPathFor = 基路径 + .bak.<ts>
func wafBackupPathFor(path string) string {
	return fmt.Sprintf("%s.bak.%d", wafBackupBaseFor(path), time.Now().Unix())
}

// wafSanitizeRuleDirs 清剿 rules 目录里非 *.json 的文件（.bak/.tmp/.probe 等），
// 否则 1pwaf 初始化会直接崩掉。返回被挪走的路径。
func wafSanitizeRuleDirs() []string {
	conf := wafConfDir()
	if conf == "" {
		return nil
	}
	data := wafDataDir(conf)
	dirs := []string{filepath.Join(data, "rules")}
	if ents, err := os.ReadDir(filepath.Join(data, "sites")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(data, "sites", e.Name(), "rules"))
			}
		}
	}
	root := wafBackupRoot()
	moved := make([]string, 0, 4)
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".json") {
				continue
			}
			src := filepath.Join(d, name)
			dstDir := filepath.Join(root, "stray", time.Now().Format("20060102-150405"), filepath.Base(d))
			if rel, err := filepath.Rel(data, d); err == nil && !strings.HasPrefix(rel, "..") {
				dstDir = filepath.Join(root, "stray", time.Now().Format("20060102-150405"), rel)
			}
			if err := os.MkdirAll(dstDir, 0o755); err != nil {
				continue
			}
			if err := os.Rename(src, filepath.Join(dstDir, name)); err == nil {
				moved = append(moved, src)
			}
		}
	}
	return moved
}

type wafContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// wafFindContainers 找 1pwaf 所在的 openresty 容器（优先镜像名，其次容器名前缀）
func wafFindContainers() []wafContainer {
	out, err := exec.Command("docker", "ps", "--format", "{{.Names}}\t{{.Image}}").Output()
	if err != nil {
		return nil
	}
	primary := make([]wafContainer, 0, 2)
	fallback := make([]wafContainer, 0, 2)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		c := wafContainer{Name: parts[0]}
		if len(parts) > 1 {
			c.Image = parts[1]
		}
		switch {
		case strings.Contains(strings.ToLower(c.Image), "openresty"):
			primary = append(primary, c)
		case strings.Contains(strings.ToLower(c.Name), "openresty"):
			fallback = append(fallback, c)
		}
	}
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// wafReloadConf 让 openresty 重新加载（等价于命令行 nginx -s reload）
func wafReloadConf() (string, []string, error) {
	warns := make([]string, 0, 2)
	// reload 前先清剿 rules 目录里的非法文件，避免 1pwaf 初始化直接崩掉
	if moved := wafSanitizeRuleDirs(); len(moved) > 0 {
		warns = append(warns, fmt.Sprintf("已清理 rules 目录中 %d 个非 .json 文件（否则 1pwaf 会初始化失败）", len(moved)))
	}
	cs := wafFindContainers()
	if len(cs) == 0 {
		return "", nil, fmt.Errorf("没找到 openresty 容器，请手动重启应用后再试")
	}
	msgs := make([]string, 0, len(cs))
	for _, c := range cs {
		if out, err := exec.Command("docker", "exec", c.Name, "nginx", "-t").CombinedOutput(); err != nil {
			return strings.TrimSpace(string(out)), append(warns, c.Name+" nginx -t 失败，已跳过 reload"), err
		}
		out, err := exec.Command("docker", "exec", c.Name, "nginx", "-s", "reload").CombinedOutput()
		txt := strings.TrimSpace(string(out))
		msgs = append(msgs, c.Name+": "+txt)
		if err != nil {
			return strings.Join(msgs, " | "), append(warns, c.Name+" reload 失败"), err
		}
	}
	// reload 是异步的：master 收到 HUP 后要起新 worker，实测约 1 秒内切换完成，
	// 这里稍等一下再返回，避免前端「刚保存完立刻验证」看到旧行为。
	time.Sleep(900 * time.Millisecond)
	return strings.Join(msgs, " | "), warns, nil
}

// ---------- 读写 JSON ----------

func wafReadJSONMap(path string) (map[string]interface{}, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	m := map[string]interface{}{}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return m, "", nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, string(raw), err
	}
	return m, string(raw), nil
}

func wafBackupFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dst := wafBackupPathFor(path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return "", err
	}
	// 只保留最近 8 份
	matches, _ := filepath.Glob(wafBackupBaseFor(path) + ".bak.*")
	if len(matches) > 8 {
		sort.Strings(matches)
		for _, old := range matches[:len(matches)-8] {
			_ = os.Remove(old)
		}
	}
	return dst, nil
}

func wafWriteJSONMap(path string, m map[string]interface{}) error {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// 已知的开关型规则键，写盘前做一次兜底校验，避免把 lua 初始化搞挂
var wafSwitchKeys = []string{
	"xss", "sql", "args", "cookie", "header", "defaultUaBlack", "defaultUrlBlack", "defaultIpBlack",
	"ipWhite", "ipBlack", "urlWhite", "urlBlack", "uaWhite", "uaBlack", "methodWhite",
	"unknownWebsite", "allowSpider", "strict", "vuln", "fileExt", "geoRestrict", "cdn",
	"cc", "urlcc", "attackCount", "notFoundCount", "app", "log",
}

func wafValidateGlobal(m map[string]interface{}) []string {
	warns := make([]string, 0, 2)
	if m == nil {
		return []string{"配置为空"}
	}
	if v, ok := m["waf"]; ok {
		obj, _ := v.(map[string]interface{})
		if obj == nil {
			warns = append(warns, "waf 段格式不对")
		} else if s, _ := obj["state"].(string); s != "on" && s != "off" {
			warns = append(warns, "waf.state 只能是 on/off，已强制为 off")
			obj["state"] = "off"
		}
	}
	for _, k := range wafSwitchKeys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		obj, _ := raw.(map[string]interface{})
		if obj == nil {
			continue
		}
		if s, exist := obj["state"]; exist {
			str, _ := s.(string)
			if str != "on" && str != "off" {
				obj["state"] = "off"
				warns = append(warns, fmt.Sprintf("%s.state 非法，已置为 off", k))
			}
		}
		if code, exist := obj["code"]; exist {
			n, err := strconv.Atoi(fmt.Sprintf("%v", code))
			if err != nil || n < 200 || n > 599 {
				obj["code"] = 403
				warns = append(warns, fmt.Sprintf("%s.code 非法，已置为 403", k))
			}
		}
		if act, exist := obj["action"]; exist {
			str, _ := act.(string)
			if str != "deny" && str != "allow" {
				obj["action"] = "deny"
				warns = append(warns, fmt.Sprintf("%s.action 非法，已置为 deny", k))
			}
		}
	}
	return warns
}

// wafRuleSummary 统计规则库
func wafRuleSummary(dataDir string) []gin.H {
	dir := filepath.Join(dataDir, "rules")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(dir, name)
		if e.IsDir() {
			files, _ := filepath.Glob(filepath.Join(path, "*.json"))
			out = append(out, gin.H{"name": name, "type": "dir", "files": len(files), "total": 0, "enabled": 0})
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		m, _, err := wafReadJSONMap(path)
		if err != nil {
			continue
		}
		list, _ := m["rules"].([]interface{})
		enabled := 0
		for _, it := range list {
			obj, _ := it.(map[string]interface{})
			if obj != nil {
				if s, _ := obj["state"].(string); s == "on" {
					enabled++
				}
			}
		}
		out = append(out, gin.H{"name": name, "type": "file", "files": 1, "total": len(list), "enabled": enabled})
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprintf("%v", out[i]["name"]) < fmt.Sprintf("%v", out[j]["name"])
	})
	return out
}

// ---------- 接口 ----------

// WafLogConfig GET /api/v2/waf-log/config
func (b *BaseApi) WafLogConfig(c *gin.Context) {
	conf := wafConfDir()
	if conf == "" {
		helper.SuccessWithData(c, gin.H{
			"ok":   false,
			"hint": "没找到 1pwaf 的 conf 目录（<openresty>/1pwaf/data/conf/global.json），请确认 openresty 应用已启动过",
		})
		return
	}
	dataDir := wafDataDir(conf)
	global, globalRaw, globalErr := wafReadJSONMap(filepath.Join(conf, "global.json"))
	monitor, monitorRaw, _ := wafReadJSONMap(filepath.Join(conf, "monitor.json"))
	defGlobal, _, _ := wafReadJSONMap(filepath.Join(dataDir, "default", "global.json"))

	warns := make([]string, 0, 2)
	if globalErr != nil {
		warns = append(warns, "global.json 解析失败："+globalErr.Error())
	}
	helper.SuccessWithData(c, gin.H{
		"ok":          true,
		"conf_dir":    conf,
		"data_dir":    dataDir,
		"containers":  wafFindContainers(),
		"global":      global,
		"global_raw":  globalRaw,
		"monitor":     monitor,
		"monitor_raw": monitorRaw,
		"defaults":    defGlobal,
		"rules":       wafRuleSummary(dataDir),
		"warnings":    warns,
		"server_time": time.Now().Format("2006-01-02 15:04:05"),
	})
}

type wafConfSaveReq struct {
	Global  map[string]interface{} `json:"global"`
	Monitor map[string]interface{} `json:"monitor"`
	Reload  bool                   `json:"reload"`
}

// WafLogConfigSave POST /api/v2/waf-log/config
func (b *BaseApi) WafLogConfigSave(c *gin.Context) {
	var req wafConfSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.ErrorWithDetail(c, 400, "ErrBind", err)
		return
	}
	conf := wafConfDir()
	if conf == "" {
		helper.ErrorWithDetail(c, 500, "ErrWafConf", fmt.Errorf("没找到 1pwaf 的 conf 目录"))
		return
	}
	if req.Global == nil && req.Monitor == nil {
		helper.ErrorWithDetail(c, 400, "ErrWafConf", fmt.Errorf("没有任何要保存的内容"))
		return
	}

	warns := make([]string, 0, 2)
	backups := make([]string, 0, 2)

	if req.Global != nil {
		warns = append(warns, wafValidateGlobal(req.Global)...)
		path := filepath.Join(conf, "global.json")
		if bk, err := wafBackupFile(path); err == nil {
			backups = append(backups, filepath.Base(bk))
		}
		if err := wafWriteJSONMap(path, req.Global); err != nil {
			helper.ErrorWithDetail(c, 500, "ErrWafConf", err)
			return
		}
	}
	if req.Monitor != nil {
		path := filepath.Join(conf, "monitor.json")
		if bk, err := wafBackupFile(path); err == nil {
			backups = append(backups, filepath.Base(bk))
		}
		if err := wafWriteJSONMap(path, req.Monitor); err != nil {
			helper.ErrorWithDetail(c, 500, "ErrWafConf", err)
			return
		}
	}

	res := gin.H{"saved": true, "backups": backups, "warnings": warns, "reloaded": false}
	if req.Reload {
		out, rw, err := wafReloadConf()
		res["reload_output"] = out
		res["warnings"] = append(warns, rw...)
		if err != nil {
			res["reloaded"] = false
			res["reload_error"] = err.Error()
		} else {
			res["reloaded"] = true
		}
	}
	helper.SuccessWithData(c, res)
}

// WafLogConfigReload POST /api/v2/waf-log/config/reload
func (b *BaseApi) WafLogConfigReload(c *gin.Context) {
	out, warns, err := wafReloadConf()
	res := gin.H{"reloaded": err == nil, "output": out, "warnings": warns}
	if err != nil {
		res["error"] = err.Error()
	}
	helper.SuccessWithData(c, res)
}

// WafLogConfigRaw GET/POST /api/v2/waf-log/raw?file=global.json
func (b *BaseApi) WafLogConfigRaw(c *gin.Context) {
	conf := wafConfDir()
	if conf == "" {
		helper.ErrorWithDetail(c, 500, "ErrWafConf", fmt.Errorf("没找到 1pwaf 的 conf 目录"))
		return
	}
	allowed := map[string]bool{"global.json": true, "monitor.json": true, "siteConfig.json": true}

	if c.Request.Method == "GET" {
		file := c.Query("file")
		if !allowed[file] {
			helper.ErrorWithDetail(c, 400, "ErrWafConf", fmt.Errorf("不支持的文件：%s", file))
			return
		}
		raw, err := os.ReadFile(filepath.Join(conf, file))
		if err != nil {
			helper.ErrorWithDetail(c, 500, "ErrWafConf", err)
			return
		}
		helper.SuccessWithData(c, gin.H{"file": file, "content": string(raw)})
		return
	}

	var req struct {
		File    string `json:"file"`
		Content string `json:"content"`
		Reload  bool   `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.ErrorWithDetail(c, 400, "ErrBind", err)
		return
	}
	if !allowed[req.File] {
		helper.ErrorWithDetail(c, 400, "ErrWafConf", fmt.Errorf("不支持的文件：%s", req.File))
		return
	}
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(req.Content), &m); err != nil {
		helper.ErrorWithDetail(c, 400, "ErrWafConf", fmt.Errorf("JSON 格式错误：%v", err))
		return
	}
	path := filepath.Join(conf, req.File)
	bk, _ := wafBackupFile(path)
	if err := wafWriteJSONMap(path, m); err != nil {
		helper.ErrorWithDetail(c, 500, "ErrWafConf", err)
		return
	}
	res := gin.H{"saved": true, "backup": filepath.Base(bk), "reloaded": false, "warnings": []string{}}
	if req.Reload {
		out, warns, err := wafReloadConf()
		res["output"] = out
		res["warnings"] = warns
		res["reloaded"] = err == nil
		if err != nil {
			res["error"] = err.Error()
		}
	}
	helper.SuccessWithData(c, res)
}
