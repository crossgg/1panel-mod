package v2

// 1Panel v2.x 社区版 WAF 日志 API（补丁文件，新增，不修改任何现有源码）
//
// 说明：
//  - 直接运行在 1Panel agent 进程内，agent 以宿主机 root 运行，天然可读 openresty 的 1pwaf/data/db
//  - 复用 agent/go.mod 里已有的 github.com/glebarez/go-sqlite（纯 Go，无 CGO，兼容 Makefile 的 CGO_ENABLED=0）
//  - 只读打开 SQLite（mode=ro + PRAGMA query_only），不会与 WAF 写入进程抢锁
//  - core 会把所有 /api/v2/*（除 /api/v2/core）通配转发到本地 agent，因此无需改 core 代码
//  - 自动探测 v1/v2 的库布局、自适应表与列，支持 v2 的 db/sites/<站点>/site_req_logs.db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/gin-gonic/gin"
	_ "github.com/glebarez/go-sqlite"
)

const wafMaxDBFiles = 80

var wafOutCols = []string{
	"id", "ip", "ip_iso", "ip_country_zh", "ip_country_en", "ip_province_zh", "ip_province_en",
	"ip_longitude", "ip_latitude", "localtime", "time", "server_name", "website_key", "host",
	"method", "uri", "user_agent", "exec_rule", "rule_type", "match_rule", "match_value",
	"nginx_log", "blocking_time", "action", "is_block", "is_attack",
}

var wafSiteCols = []string{
	"id", "localtime", "time", "ip", "method", "uri", "status_code", "status",
	"request_time", "browser", "os", "user_agent", "referer", "host",
}

var wafRuleLabels = map[string]string{
	"urlDefense": "URL 规则", "urlHelper": "禁止访问的 URL", "dirFilter": "目录过滤",
	"sqlInject": "SQL 注入", "xss": "XSS", "phpExec": "PHP 脚本执行",
	"oneWordTrojan": "一句话木马", "appFilter": "应用危险目录过滤", "webshell": "Webshell",
	"protocolFilter": "协议过滤", "javaFileter": "Java 危险文件过滤", "scannerFilter": "扫描器过滤",
	"escapeFilter": "转义过滤", "customRule": "自定义规则", "httpMethod": "HTTP 方法过滤",
	"fileExt": "文件上传限制", "fileExtHelper": "禁止上传的文件扩展名", "fiveSeconds": "5 秒验证",
	"acl": "ACL", "captcha": "人机验证", "uaBlack": "User-Agent 黑名单",
	"urlBlockList": "URL 黑名单", "ipBlack": "IP 黑名单", "unknownWebsite": "未授权域名访问",
	"geoRestrict": "地区访问限制", "attackCount": "攻击频率限制", "notFoundCount": "404 频率限制",
	"cookieDefense": "Cookie 规则", "headerDefense": "Header 规则", "defaultUaBlack": "User-Agent 规则",
	"argsDefense": "参数规则", "httpRule": "HTTP 规则", "defaultUrlBlack": "URL 规则",
	"defaultIpBlack": "恶意 IP 组", "fileExtCheck": "文件上传限制",
	"sql": "SQL 注入", "cc": "CC 防护", "urlcc": "URL CC 防护", "vuln": "漏洞规则",
	"vulnCheck": "漏洞规则", "strict": "严格模式", "args": "参数规则", "cookie": "Cookie 规则",
	"header": "Header 规则", "methodWhite": "HTTP 方法白名单", "cdn": "CDN 配置",
	"ipWhite": "IP 白名单", "urlWhite": "URL 白名单", "uaWhite": "UA 白名单",
	"urlBlack": "URL 黑名单", "allowSpider": "爬虫放行", "spider": "爬虫规则",
	"ipGroup": "IP 组", "redirect": "重定向", "unknown": "未授权域名", "geo": "地区限制",
	// v1/第三方规则库里常见的下划线式命名
	"sql_injection": "SQL 注入", "sqlInjection": "SQL 注入", "sql_inject": "SQL 注入",
	"xss_injection": "XSS", "xssAttack": "XSS", "xss_attack": "XSS",
	"command_injection": "命令注入", "cmd_injection": "命令注入", "rce": "远程命令执行",
	"path_traversal": "路径穿越", "directory_traversal": "路径穿越", "file_inclusion": "文件包含",
	"file_upload": "文件上传", "webshell_upload": "Webshell 上传", "scanner": "扫描器",
	"scanner_scan": "扫描器", "cc_attack": "CC 防护", "ccAttack": "CC 防护",
	"ssrf": "SSRF", "xxe": "XXE", "brute_force": "暴力破解", "bruteForce": "暴力破解",
	"bot": "爬虫/机器人", "spider_rule": "爬虫规则", "ip_black": "IP 黑名单",
	"ua_black": "User-Agent 黑名单", "url_black": "URL 黑名单", "csrf": "CSRF",
	"backdoor": "后门", "malware": "恶意文件", "leak": "信息泄露", "sensitive": "敏感信息",
}

type wafSource struct {
	Path    string
	Table   string
	Kind    string // log | stat | sitelog
	Site    string
	Cols    map[string]bool
	TimeCol string
}

type wafDBSet struct {
	Dirs    []string
	Files   []string
	Sources []wafSource
	Conns   map[string]*sql.DB
}

func (s *wafDBSet) Close() {
	for _, db := range s.Conns {
		_ = db.Close()
	}
}

type wafFilters struct {
	Page       int
	Size       int
	Website    string
	URI        string
	IP         string
	Site       string
	Rules      []string
	OnlyAttack bool
}

func wafQI(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func wafOpenRO(path string) (*sql.DB, error) {
	dsns := []string{"file:" + filepath.ToSlash(path) + "?mode=ro", path}
	for _, dsn := range dsns {
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			continue
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		if _, err = db.Exec("PRAGMA query_only = ON"); err != nil {
			_ = db.Close()
			continue
		}
		_, _ = db.Exec("PRAGMA busy_timeout = 3000")
		return db, nil
	}
	return nil, fmt.Errorf("cannot open %s", path)
}

func wafTableCols(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + wafQI(table) + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk) == nil {
			cols[name] = true
		}
	}
	return cols, rows.Err()
}

func wafClassify(table string, cols map[string]bool) string {
	t := strings.ToLower(table)
	if t == "waf_stat" || (cols["req_count"] && cols["attack_count"]) {
		return "stat"
	}
	if strings.Contains(t, "site_req_log") {
		return "sitelog"
	}
	if strings.Contains(t, "req_log") {
		return "log"
	}
	if cols["ip"] && cols["uri"] && (cols["localtime"] || cols["time"] || cols["id"]) {
		return "log"
	}
	return "skip"
}

// ============================================================================
// 1Panel v2 真实布局（1pwaf 2.0）
//
//   <openresty>/1pwaf/data/db/
//     global/default.db      actions / methods / os / browsers / spiders / iso ...
//     global/location.db     locations(id, iso, country_zh, ..., longitude, latitude)
//     global/status_codes.db status_codes
//     waf/attack_logs.db     attack_logs(id, event_id, website_id, ip_id, host_id, rule_id,
//                                     rule_type_id, match_value_id, nginx_log_id, action_id,
//                                     uri_id, req_uri_id, ip_location_id, is_block, is_attack,
//                                     iso_id, localtime, time)
//     waf/nginx_logs.db      nginx_logs(id, event_id, method_id, ua_id, remote_port, status_code, nginx_log)
//     waf/ips.db uris.db req_uris.db hosts.db user_agents.db rules.db rule_types.db
//         match_values.db websites.db      —— 均为 (id, value) 维度表
//     waf/waf_stat.db        waf_stat(id, day, year, req_count, attack_count, count4xx, count5xx, create_date)
//
// attack_logs 只存外键，必须靠维度表翻译；因此这里用「内存维度映射」而不是跨库 ATTACH
// （SQLite 默认最多 10 个 attached database，维度表有 12 个，会超限）。
// ============================================================================

type wafV2 struct {
	Base   string
	Conns  map[string]*sql.DB
	Dims   map[string]map[int64]string
	DimsAt time.Time
	Warn   []string
}

var wafV2DimNames = []string{
	"websites", "hosts", "ips", "rules", "rule_types", "match_values",
	"uris", "req_uris", "user_agents",
}

func wafV2Roots() []string {
	roots := make([]string, 0)
	seen := make(map[string]bool)
	patterns := make([]string, 0)
	if v := os.Getenv("PANEL_WAF_DB_DIR"); v != "" {
		patterns = append(patterns, v)
	}
	if global.Dir.AppInstallDir != "" {
		patterns = append(patterns, filepath.Join(global.Dir.AppInstallDir, "openresty", "*", "1pwaf", "data", "db"))
	}
	patterns = append(patterns,
		"/opt/1panel/apps/openresty/*/1pwaf/data/db",
		"/usr/local/openresty/1pwaf/data/db",
	)
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		if len(matches) == 0 {
			matches = []string{pattern}
		}
		for _, dir := range matches {
			abs, err := filepath.Abs(dir)
			if err != nil || seen[abs] {
				continue
			}
			st, err := os.Stat(filepath.Join(abs, "waf", "attack_logs.db"))
			if err != nil || st.IsDir() {
				continue
			}
			seen[abs] = true
			roots = append(roots, abs)
		}
	}
	return roots
}

func wafV2Discover() []*wafV2 {
	roots := wafV2Roots()
	sets := make([]*wafV2, 0, len(roots))
	for _, r := range roots {
		sets = append(sets, &wafV2{Base: r, Conns: make(map[string]*sql.DB)})
	}
	return sets
}

func (v *wafV2) close() {
	for _, db := range v.Conns {
		if db != nil {
			_ = db.Close()
		}
	}
}

func wafHasTable(db *sql.DB, table string) bool {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", table)
	if err != nil {
		return false
	}
	defer rows.Close()
	return rows.Next()
}

func (v *wafV2) db(path string) *sql.DB {
	if d, ok := v.Conns[path]; ok {
		return d
	}
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		v.Conns[path] = nil
		return nil
	}
	d, err := wafOpenRO(path)
	if err != nil {
		v.Warn = append(v.Warn, filepath.Base(path)+": "+err.Error())
		v.Conns[path] = nil
		return nil
	}
	v.Conns[path] = d
	return d
}

func (v *wafV2) readKV(path, table string) map[int64]string {
	out := make(map[int64]string)
	db := v.db(path)
	if db == nil || !wafHasTable(db, table) {
		return out
	}
	rows, err := db.Query("SELECT id, value FROM " + wafQI(table))
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var val sql.NullString
		if rows.Scan(&id, &val) == nil && val.Valid {
			out[id] = val.String
		}
	}
	return out
}

func (v *wafV2) loadDims() {
	if v.Dims != nil && time.Since(v.DimsAt) < 30*time.Second {
		return
	}
	dims := make(map[string]map[int64]string, len(wafV2DimNames)+2)
	for _, n := range wafV2DimNames {
		dims[n] = v.readKV(filepath.Join(v.Base, "waf", n+".db"), n)
	}
	def := filepath.Join(v.Base, "global", "default.db")
	dims["actions"] = v.readKV(def, "actions")
	dims["methods"] = v.readKV(def, "methods")
	v.Dims = dims
	v.DimsAt = time.Now()
}

func wafInt64(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case int64:
		return val, true
	case int:
		return int64(val), true
	case float64:
		return int64(val), true
	case []byte:
		n, err := strconv.ParseInt(string(val), 10, 64)
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(val, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func wafStr(v interface{}) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case []byte:
		return string(val)
	}
	return fmt.Sprintf("%v", v)
}

// 1pwaf 2.0 落库的 localtime 实际是 UTC（容器时区未生效时），
// 统一用 unix 时间戳按面板本机时区重新格式化，避免面板里显示差 8 小时。
func wafLocalTime(raw interface{}, tsec interface{}) interface{} {
	if ts := wafToFloat(tsec); ts > 0 {
		return time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
	}
	return raw
}

func (v *wafV2) dimValue(name string, id interface{}) string {
	m, ok := v.Dims[name]
	if !ok || m == nil {
		return ""
	}
	if n, ok := wafInt64(id); ok {
		return m[n]
	}
	return ""
}

// idsByValue 在维度表里按精确值反查主键
func (v *wafV2) idsByValue(name, value string) []int64 {
	out := make([]int64, 0, 1)
	for id, val := range v.Dims[name] {
		if val == value {
			out = append(out, id)
		}
	}
	return out
}

// idsByLike 在维度表里按包含匹配反查主键
func (v *wafV2) idsByLike(name, sub string) []int64 {
	out := make([]int64, 0, 8)
	low := strings.ToLower(sub)
	for id, val := range v.Dims[name] {
		if strings.Contains(strings.ToLower(val), low) {
			out = append(out, id)
		}
	}
	return out
}

func wafInClause(col string, ids []int64) (string, []interface{}) {
	if len(ids) == 0 {
		return "", nil
	}
	holders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	return wafQI(col) + " IN (" + holders + ")", args
}

func (v *wafV2) where(f wafFilters) (string, []interface{}) {
	conds := []string{"1=1"}
	args := make([]interface{}, 0)
	if f.Website != "" {
		ids := v.idsByValue("websites", f.Website)
		if len(ids) == 0 {
			ids = v.idsByValue("hosts", f.Website)
		}
		if len(ids) == 0 {
			conds = append(conds, "1=0")
		} else if c, a := wafInClause("website_id", ids); c != "" {
			conds = append(conds, c)
			args = append(args, a...)
		}
	}
	if f.IP != "" {
		ids := v.idsByValue("ips", f.IP)
		if len(ids) == 0 {
			conds = append(conds, "1=0")
		} else if c, a := wafInClause("ip_id", ids); c != "" {
			conds = append(conds, c)
			args = append(args, a...)
		}
	}
	if f.URI != "" {
		ids := v.idsByLike("uris", f.URI)
		if len(ids) == 0 {
			conds = append(conds, "1=0")
		} else if c, a := wafInClause("uri_id", ids); c != "" {
			conds = append(conds, c)
			args = append(args, a...)
		}
	}
	if len(f.Rules) > 0 {
		ruleIDs := make([]int64, 0, 8)
		typeIDs := make([]int64, 0, 8)
		for _, r := range f.Rules {
			ruleIDs = append(ruleIDs, v.idsByValue("rules", r)...)
			typeIDs = append(typeIDs, v.idsByValue("rule_types", r)...)
		}
		parts := make([]string, 0, 2)
		if c, a := wafInClause("rule_id", ruleIDs); c != "" {
			parts = append(parts, c)
			args = append(args, a...)
		}
		if c, a := wafInClause("rule_type_id", typeIDs); c != "" {
			parts = append(parts, c)
			args = append(args, a...)
		}
		if len(parts) == 0 {
			conds = append(conds, "1=0")
		} else {
			conds = append(conds, "("+strings.Join(parts, " OR ")+")")
		}
	}
	if f.OnlyAttack {
		conds = append(conds, wafQI("is_attack")+" = 1")
	}
	return strings.Join(conds, " AND "), args
}

// wafV2NginxLogs 批量取 nginx_logs（method/ua/状态码/原始日志）
func (v *wafV2) wafV2NginxLogs(ids []int64) map[int64]map[string]interface{} {
	out := make(map[int64]map[string]interface{}, len(ids))
	if len(ids) == 0 {
		return out
	}
	db := v.db(filepath.Join(v.Base, "waf", "nginx_logs.db"))
	if db == nil || !wafHasTable(db, "nginx_logs") {
		return out
	}
	c, args := wafInClause("id", ids)
	rows, err := db.Query("SELECT id, method_id, ua_id, remote_port, status_code, nginx_log FROM nginx_logs WHERE "+c, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var methodID, uaID, remotePort, statusCode sql.NullInt64
		var nginxLog sql.NullString
		if rows.Scan(&id, &methodID, &uaID, &remotePort, &statusCode, &nginxLog) != nil {
			continue
		}
		out[id] = map[string]interface{}{
			"method": methodID.Int64, "ua": uaID.Int64,
			"remote_port": remotePort.Int64, "status_code": statusCode.Int64,
			"nginx_log": nginxLog.String,
		}
	}
	return out
}

func (v *wafV2) wafV2Locations(ids []int64) map[int64]map[string]interface{} {
	out := make(map[int64]map[string]interface{}, len(ids))
	if len(ids) == 0 {
		return out
	}
	db := v.db(filepath.Join(v.Base, "global", "location.db"))
	if db == nil || !wafHasTable(db, "locations") {
		return out
	}
	cols, err := wafTableCols(db, "locations")
	if err != nil {
		return out
	}
	want := make([]string, 0, 8)
	for _, c := range []string{"iso", "country_zh", "country_en", "province_zh", "province_en", "longitude", "latitude"} {
		if cols[c] {
			want = append(want, c)
		}
	}
	if len(want) == 0 {
		return out
	}
	c, args := wafInClause("id", ids)
	sel := "id"
	for _, w := range want {
		sel += ", " + wafQI(w)
	}
	rows, err := db.Query("SELECT "+sel+" FROM locations WHERE "+c, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		values := make([]interface{}, len(want)+1)
		pointers := make([]interface{}, len(values))
		for i := range values {
			pointers[i] = &values[i]
		}
		if rows.Scan(pointers...) != nil {
			continue
		}
		id, _ := wafInt64(values[0])
		m := make(map[string]interface{}, len(want))
		for i, name := range want {
			m[name] = wafNormalizeVal(values[i+1])
		}
		out[id] = m
	}
	return out
}

// list 返回本实例的一页数据（offset+size 条，便于多实例合并后切页）
func (v *wafV2) list(f wafFilters) ([]map[string]interface{}, int, []string) {
	v.loadDims()
	db := v.db(filepath.Join(v.Base, "waf", "attack_logs.db"))
	if db == nil {
		return nil, 0, v.Warn
	}
	where, args := v.where(f)
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM attack_logs WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, append(v.Warn, err.Error())
	}
	offset := (f.Page - 1) * f.Size
	limit := offset + f.Size
	if limit < 1 {
		limit = f.Size
	}
	query := "SELECT * FROM attack_logs WHERE " + where + " ORDER BY " + wafQI("time") + " DESC LIMIT ?"
	rows, err := db.Query(query, append(append([]interface{}{}, args...), limit)...)
	if err != nil {
		return nil, 0, append(v.Warn, err.Error())
	}
	cols, _ := rows.Columns()
	rawRows := make([]map[string]interface{}, 0, limit)
	for rows.Next() {
		values := make([]interface{}, len(cols))
		pointers := make([]interface{}, len(cols))
		for i := range values {
			pointers[i] = &values[i]
		}
		if rows.Scan(pointers...) != nil {
			continue
		}
		m := make(map[string]interface{}, len(cols))
		for i, c := range cols {
			m[c] = wafNormalizeVal(values[i])
		}
		rawRows = append(rawRows, m)
	}
	_ = rows.Close()

	// 第二段：nginx_logs（一次一个 id，日志表按 nginx_log_id 关联）
	nginxIDs := make([]int64, 0, len(rawRows))
	for _, r := range rawRows {
		if id, ok := wafInt64(r["nginx_log_id"]); ok && id > 0 {
			nginxIDs = append(nginxIDs, id)
		}
	}
	nginxMap := v.wafV2NginxLogs(nginxIDs)

	locIDs := make([]int64, 0, len(rawRows))
	for _, r := range rawRows {
		if id, ok := wafInt64(r["ip_location_id"]); ok && id > 0 {
			locIDs = append(locIDs, id)
		}
	}
	locMap := v.wafV2Locations(locIDs)

	out := make([]map[string]interface{}, 0, len(rawRows))
	for _, r := range rawRows {
		nl := map[string]interface{}(nil)
		if id, ok := wafInt64(r["nginx_log_id"]); ok {
			nl = nginxMap[id]
		}
		loc := map[string]interface{}(nil)
		if id, ok := wafInt64(r["ip_location_id"]); ok {
			loc = locMap[id]
		}
		row := map[string]interface{}{
			"id":          r["id"],
			"event_id":    r["event_id"],
			"time":        r["time"],
			"localtime":   wafLocalTime(r["localtime"], r["time"]),
			"ip":          v.dimValue("ips", r["ip_id"]),
			"website_key": v.dimValue("websites", r["website_id"]),
			"server_name": v.dimValue("hosts", r["host_id"]),
			"host":        v.dimValue("hosts", r["host_id"]),
			"uri":         v.dimValue("uris", r["uri_id"]),
			"req_uri":     v.dimValue("req_uris", r["req_uri_id"]),
			"user_agent":  v.dimValue("user_agents", r["ua_id"]),
			"exec_rule":   wafTranslate(v.dimValue("rules", r["rule_id"])),
			"rule_type":   wafTranslate(v.dimValue("rule_types", r["rule_type_id"])),
			"match_value": v.dimValue("match_values", r["match_value_id"]),
			"action":      v.dimValue("actions", r["action_id"]),
			"is_block":    r["is_block"],
			"is_attack":   r["is_attack"],
			"_db":         "attack_logs.db",
			"_site":       v.dimValue("websites", r["website_id"]),
			"_sort":       wafToFloat(r["time"]),
		}
		if nl != nil {
			row["method"] = v.dimValue("methods", nl["method"])
			if row["user_agent"] == "" {
				row["user_agent"] = v.dimValue("user_agents", nl["ua"])
			}
			row["remote_port"] = nl["remote_port"]
			row["status_code"] = nl["status_code"]
			row["nginx_log"] = nl["nginx_log"]
		}
		if loc != nil {
			row["ip_iso"] = loc["iso"]
			row["ip_country_zh"] = loc["country_zh"]
			row["ip_country_en"] = loc["country_en"]
			row["ip_province_zh"] = loc["province_zh"]
			row["ip_province_en"] = loc["province_en"]
			row["ip_longitude"] = loc["longitude"]
			row["ip_latitude"] = loc["latitude"]
		}
		out = append(out, row)
	}
	return out, total, v.Warn
}

// stat 直接读 waf_stat（1pwaf 自己维护的日统计）
func (v *wafV2) stat(today string) gin.H {
	res := gin.H{
		"req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0,
		"total_logs": 0, "day": today, "source": "waf_stat",
	}
	db := v.db(filepath.Join(v.Base, "waf", "waf_stat.db"))
	if db == nil || !wafHasTable(db, "waf_stat") {
		return res
	}
	rows, err := db.Query("SELECT * FROM waf_stat")
	if err != nil {
		return res
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	best := map[string]interface{}(nil)
	for rows.Next() {
		values := make([]interface{}, len(cols))
		pointers := make([]interface{}, len(cols))
		for i := range values {
			pointers[i] = &values[i]
		}
		if rows.Scan(pointers...) != nil {
			continue
		}
		row := make(map[string]interface{}, len(cols))
		for i, c := range cols {
			row[c] = wafNormalizeVal(values[i])
		}
		best = wafPickStatRow(best, row, today)
	}
	if best != nil {
		for _, k := range []string{"req_count", "attack_count", "count4xx", "count5xx", "day"} {
			if val, ok := best[k]; ok && val != nil {
				res[k] = val
			}
		}
		if val, ok := best["day"]; ok && val != nil {
			res["day"] = val
		}
	}
	// 拦截明细总数（不受日统计限制时更有参考价值）
	logsDB := v.db(filepath.Join(v.Base, "waf", "attack_logs.db"))
	if logsDB != nil {
		var n int
		if logsDB.QueryRow("SELECT COUNT(*) FROM attack_logs").Scan(&n) == nil {
			res["total_logs"] = n
		}
	}
	return res
}

func (v *wafV2) sites() []string {
	v.loadDims()
	seen := make(map[string]bool)
	out := make([]string, 0, 8)
	for _, val := range v.Dims["websites"] {
		if val == "" || seen[val] {
			continue
		}
		seen[val] = true
		out = append(out, val)
	}
	if len(out) == 0 {
		for _, val := range v.Dims["hosts"] {
			if val == "" || seen[val] {
				continue
			}
			seen[val] = true
			out = append(out, val)
		}
	}
	sort.Strings(out)
	return out
}

func (v *wafV2) rules() []gin.H {
	v.loadDims()
	seen := make(map[string]bool)
	out := make([]gin.H, 0, 16)
	for _, name := range []string{"rules", "rule_types"} {
		for _, val := range v.Dims[name] {
			if val == "" || seen[val] {
				continue
			}
			seen[val] = true
			out = append(out, gin.H{"value": val, "label": wafTranslate(val)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["value"].(string) < out[j]["value"].(string)
	})
	return out
}

func (v *wafV2) describe() gin.H {
	v.loadDims()
	files := make([]string, 0, 24)
	for _, sub := range []string{"waf", "global"} {
		matches, _ := filepath.Glob(filepath.Join(v.Base, sub, "*.db"))
		files = append(files, matches...)
	}
	sort.Strings(files)
	dims := gin.H{}
	for _, n := range append(append([]string{}, wafV2DimNames...), "actions", "methods") {
		dims[n] = len(v.Dims[n])
	}
	return gin.H{
		"layout": "v2-1pwaf", "base": v.Base, "db_files": files, "dims": dims,
	}
}


func wafTimeCol(cols map[string]bool) string {
	for _, c := range []string{"time", "localtime", "id"} {
		if cols[c] {
			return c
		}
	}
	return "rowid"
}

// wafRuleCols 返回该库里代表“命中规则”的真实列名。
// v1 用 rule，v2 用 exec_rule / rule_type，这里统一识别，避免列名不一致导致筛选与规则下拉为空。
func wafRuleCols(cols map[string]bool) []string {
	out := make([]string, 0, 3)
	for _, c := range []string{"exec_rule", "rule_type", "rule"} {
		if cols[c] {
			out = append(out, c)
		}
	}
	return out
}

func wafSiteFromPath(path string) string {
	p := filepath.ToSlash(path)
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if (part == "sites" || part == "monitor") && i+2 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func wafDiscover() *wafDBSet {
	set := &wafDBSet{Conns: make(map[string]*sql.DB)}
	patterns := make([]string, 0)
	if v := os.Getenv("PANEL_WAF_DB_DIR"); v != "" {
		patterns = append(patterns, v)
	}
	if global.Dir.AppInstallDir != "" {
		patterns = append(patterns, filepath.Join(global.Dir.AppInstallDir, "openresty", "*", "1pwaf", "data", "db"))
	}
	patterns = append(patterns,
		"/opt/1panel/apps/openresty/*/1pwaf/data/db",
		"/usr/local/openresty/1pwaf/data/db",
	)
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		if len(matches) == 0 && !strings.Contains(pattern, "*") {
			matches = []string{pattern}
		}
		for _, dir := range matches {
			abs, err := filepath.Abs(dir)
			if err != nil {
				continue
			}
			info, err := os.Stat(abs)
			if err != nil || !info.IsDir() || seen[abs] {
				continue
			}
			seen[abs] = true
			set.Dirs = append(set.Dirs, abs)
		}
	}

	for _, dir := range set.Dirs {
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				rel, _ := filepath.Rel(dir, path)
				if rel != "." && strings.Count(rel, string(os.PathSeparator)) >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			if len(set.Files) >= wafMaxDBFiles {
				return nil
			}
			name := entry.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".db" && ext != ".sqlite" && ext != ".sqlite3" {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Size() < 100 {
				return nil
			}
			set.Files = append(set.Files, path)
			return nil
		})
	}

	for _, file := range set.Files {
		db, err := wafOpenRO(file)
		if err != nil {
			continue
		}
		set.Conns[file] = db
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
		if err != nil {
			continue
		}
		tables := make([]string, 0)
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				tables = append(tables, name)
			}
		}
		_ = rows.Close()
		for _, table := range tables {
			if strings.HasPrefix(table, "sqlite_") {
				continue
			}
			cols, err := wafTableCols(db, table)
			if err != nil || len(cols) == 0 {
				continue
			}
			kind := wafClassify(table, cols)
			if kind == "skip" {
				continue
			}
			set.Sources = append(set.Sources, wafSource{
				Path: file, Table: table, Kind: kind, Site: wafSiteFromPath(file),
				Cols: cols, TimeCol: wafTimeCol(cols),
			})
		}
	}
	return set
}

func wafLikeEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "%", `\%`)
	return strings.ReplaceAll(v, "_", `\_`)
}

func wafWhere(s wafSource, f wafFilters, withRules bool) (string, []interface{}) {
	conds := []string{"1=1"}
	args := make([]interface{}, 0)
	if withRules && f.Website != "" {
		for _, col := range []string{"website_key", "server_name", "host"} {
			if s.Cols[col] {
				conds = append(conds, wafQI(col)+" = ?")
				args = append(args, f.Website)
				break
			}
		}
	}
	if f.IP != "" && s.Cols["ip"] {
		conds = append(conds, `"ip" = ?`)
		args = append(args, f.IP)
	}
	if f.URI != "" && s.Cols["uri"] {
		conds = append(conds, `"uri" LIKE ? ESCAPE '\'`)
		args = append(args, "%"+wafLikeEscape(f.URI)+"%")
	}
	if withRules && len(f.Rules) > 0 {
		holders := strings.TrimSuffix(strings.Repeat("?,", len(f.Rules)), ",")
		parts := make([]string, 0)
		for _, col := range wafRuleCols(s.Cols) {
			parts = append(parts, wafQI(col)+" IN ("+holders+")")
			for _, v := range f.Rules {
				args = append(args, v)
			}
		}
		if len(parts) > 0 {
			conds = append(conds, "("+strings.Join(parts, " OR ")+")")
		}
	}
	if withRules && f.OnlyAttack {
		parts := make([]string, 0)
		if s.Cols["is_attack"] {
			parts = append(parts, wafQI("is_attack")+" = 1")
		}
		if s.Cols["action"] {
			parts = append(parts, wafQI("action")+" = 'deny'")
		}
		// 没有 is_attack / action 的老库：命中规则列非空即为拦截记录
		for _, col := range wafRuleCols(s.Cols) {
			if col == "rule" || col == "exec_rule" {
				parts = append(parts, "("+wafQI(col)+" IS NOT NULL AND "+wafQI(col)+" <> '')")
			}
		}
		if len(parts) > 0 {
			conds = append(conds, "("+strings.Join(parts, " OR ")+")")
		}
	}
	return strings.Join(conds, " AND "), args
}

func wafToFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int64:
		return float64(val)
	case int:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

func wafNormalizeVal(v interface{}) interface{} {
	switch val := v.(type) {
	case []byte:
		return string(val)
	case time.Time:
		return val.Format("2006-01-02 15:04:05")
	}
	return v
}

func wafTranslate(v interface{}) interface{} {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return v
	}
	if label, ok := wafRuleLabels[s]; ok {
		return label
	}
	return s
}

// wafSortKey 生成跨库归并排序用的数值时间戳（秒）。
// v1 的 time 是字符串、v2 的 localtime 也可能是字符串，统一解析。
func wafSortKey(row map[string]interface{}) float64 {
	for _, key := range []string{"time", "localtime", "create_date"} {
		v, ok := row[key]
		if !ok || v == nil {
			continue
		}
		switch val := v.(type) {
		case int64:
			if val > 0 {
				return float64(val)
			}
		case float64:
			if val > 0 {
				return val
			}
		case string:
			if val == "" {
				continue
			}
			if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
				return float64(n)
			}
			for _, layout := range []string{
				"2006-01-02 15:04:05", "2006-01-02T15:04:05Z07:00",
				"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05 -0700 MST",
				"2006-01-02",
			} {
				if t, err := time.ParseInLocation(layout, val, time.Local); err == nil {
					return float64(t.Unix())
				}
			}
		}
	}
	return 0
}

func wafNormalizeRow(row map[string]interface{}, s wafSource, outCols []string) map[string]interface{} {
	out := make(map[string]interface{})
	for _, col := range outCols {
		out[col] = row[col]
	}
	if v, ok := out["website_key"]; !ok || v == nil || v == "" {
		for _, col := range []string{"server_name", "host"} {
			if v2, ok := row[col]; ok && v2 != nil && v2 != "" {
				out["website_key"] = v2
				break
			}
		}
		if v, ok := out["website_key"]; !ok || v == nil || v == "" {
			out["website_key"] = s.Site
		}
	}
	// 规则列别名：老库只有 rule，前端统一按 exec_rule 展示
	if v, ok := row["rule"]; ok && v != nil && v != "" {
		if cur, _ := out["exec_rule"].(string); cur == "" {
			out["exec_rule"] = v
		}
	}
	if _, ok := out["exec_rule"]; ok {
		out["exec_rule"] = wafTranslate(out["exec_rule"])
	}
	if _, ok := out["rule_type"]; ok {
		out["rule_type"] = wafTranslate(out["rule_type"])
	}
	// is_attack 缺失时按规则是否命中推导，保证前端“仅看攻击”开关可用
	if v, ok := out["is_attack"]; !ok || v == nil || v == "" || v == 0 || v == false {
		if ru, _ := out["exec_rule"].(string); ru != "" {
			out["is_attack"] = true
		} else if action, _ := out["action"].(string); action == "deny" {
			out["is_attack"] = true
		}
	}
	out["_sort"] = wafSortKey(row)
	out["_db"] = filepath.Base(s.Path)
	out["_site"] = s.Site
	return out
}

func wafParseFilters(c *gin.Context) wafFilters {
	atoi := func(v string, def int) int {
		n, err := strconv.Atoi(v)
		if err != nil {
			return def
		}
		return n
	}
	f := wafFilters{
		Page: atoi(c.Query("page"), 1), Size: atoi(c.Query("size"), 10),
		Website: c.Query("website_key"), URI: c.Query("uri"),
		IP: c.Query("ip"), Site: c.Query("site"),
		OnlyAttack: c.Query("only_attack") == "1",
	}
	if arr, ok := c.GetQueryArray("exec_rule"); ok {
		for _, v := range arr {
			for _, item := range strings.Split(v, ",") {
				if item = strings.TrimSpace(item); item != "" {
					f.Rules = append(f.Rules, item)
				}
			}
		}
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Size < 1 {
		f.Size = 10
	}
	if f.Size > 200 {
		f.Size = 200
	}
	return f
}

func wafQuery(set *wafDBSet, kind string, f wafFilters, outCols []string, withRules bool) gin.H {
	offset := (f.Page - 1) * f.Size
	limit := offset + f.Size
	total := 0
	rowsAll := make([]map[string]interface{}, 0)
	warnings := make([]string, 0)
	for _, s := range set.Sources {
		if s.Kind != kind {
			continue
		}
		if f.Site != "" && s.Site != "" && s.Site != f.Site {
			continue
		}
		db := set.Conns[s.Path]
		if db == nil {
			continue
		}
		where, args := wafWhere(s, f, withRules)
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM "+wafQI(s.Table)+" WHERE "+where, args...).Scan(&count); err != nil {
			warnings = append(warnings, filepath.Base(s.Path)+": "+err.Error())
			continue
		}
		total += count
		query := "SELECT * FROM " + wafQI(s.Table) + " WHERE " + where +
			" ORDER BY " + wafQI(s.TimeCol) + " DESC LIMIT ?"
		queryArgs := append(append([]interface{}{}, args...), limit)
		rows, err := db.Query(query, queryArgs...)
		if err != nil {
			warnings = append(warnings, filepath.Base(s.Path)+": "+err.Error())
			continue
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]interface{}, len(cols))
			pointers := make([]interface{}, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if rows.Scan(pointers...) != nil {
				continue
			}
			row := make(map[string]interface{})
			for i, col := range cols {
				row[col] = wafNormalizeVal(values[i])
			}
			rowsAll = append(rowsAll, wafNormalizeRow(row, s, outCols))
		}
		_ = rows.Close()
	}
	sort.SliceStable(rowsAll, func(i, j int) bool {
		return wafToFloat(rowsAll[i]["_sort"]) > wafToFloat(rowsAll[j]["_sort"])
	})
	if offset > len(rowsAll) {
		offset = len(rowsAll)
	}
	end := offset + f.Size
	if end > len(rowsAll) {
		end = len(rowsAll)
	}
	return gin.H{
		"data": rowsAll[offset:end], "total": total,
		"page": f.Page, "size": f.Size, "warnings": warnings,
	}
}

func wafColKeys(cols map[string]bool) []string {
	keys := make([]string, 0, len(cols))
	for k := range cols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var (
	wafStatMu   sync.Mutex
	wafStatKey  string
	wafStatAt   time.Time
	wafStatData gin.H
)

// WafLogDiag 返回探测到的目录、库文件与表，用于部署自检
func (b *BaseApi) WafLogDiag(c *gin.Context) {
	today := time.Now().Format("2006-01-02")
	sets := wafV2Discover()
	defer func() {
		for _, s := range sets {
			s.close()
		}
	}()
	v2Info := make([]gin.H, 0, len(sets))
	layout := "none"
	for _, s := range sets {
		v2Info = append(v2Info, s.describe())
		layout = "v2-1pwaf"
	}

	set := &wafDBSet{Conns: make(map[string]*sql.DB)}
	sources := make([]gin.H, 0)
	if layout == "none" {
		// 只有找不到 v2 新布局时才回退扫 v1 老布局（少开 20 个库，避免拖慢）
		set = wafDiscover()
		for _, s := range set.Sources {
			sources = append(sources, gin.H{
				"file": s.Path, "table": s.Table, "kind": s.Kind,
				"site": s.Site, "columns": wafColKeys(s.Cols),
			})
		}
		if len(sources) > 0 {
			layout = "legacy"
		}
	}
	defer set.Close()

	helper.SuccessWithData(c, gin.H{
		"ok": layout != "none", "layout": layout, "today": today,
		"v2": v2Info, "app_install_dir": global.Dir.AppInstallDir,
		"found_dirs": set.Dirs, "db_files": set.Files, "sources": sources,
		"hint": "v2 新布局判据：<openresty>/1pwaf/data/db/waf/attack_logs.db 存在；" +
			"若 ok=false，检查 openresty 是否已启动过，或设置环境变量 PANEL_WAF_DB_DIR 指向 1pwaf/data/db",
	})
}

// wafPickStatRow 在 waf_stat 里挑选“今天”那一行；没有今天则退化为日期最大的行。
func wafPickStatRow(cur, row map[string]interface{}, today string) map[string]interface{} {
	dayOf := func(m map[string]interface{}) string {
		for _, key := range []string{"day", "create_date", "date", "stat_date"} {
			if v, ok := m[key]; ok && v != nil {
				s := fmt.Sprintf("%v", v)
				if len(s) >= 10 {
					return s[:10]
				}
				return s
			}
		}
		return ""
	}
	d := dayOf(row)
	if d == today {
		return row
	}
	if cur == nil {
		return row
	}
	if d > dayOf(cur) {
		return row
	}
	return cur
}

// WafLogStat 今日统计（优先 v2 的 waf_stat，其次 v1 老布局聚合）
func (b *BaseApi) WafLogStat(c *gin.Context) {
	today := time.Now().Format("2006-01-02")
	if sets := wafV2Discover(); len(sets) > 0 {
		defer func() {
			for _, s := range sets {
				s.close()
			}
		}()
		merged := gin.H{
			"req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0,
			"total_logs": 0, "day": today, "source": "waf_stat", "warnings": []string{},
		}
		warnings := make([]string, 0)
		for _, s := range sets {
			r := s.stat(today)
			for _, k := range []string{"req_count", "attack_count", "count4xx", "count5xx", "total_logs"} {
				merged[k] = int(wafToFloat(merged[k])) + int(wafToFloat(r[k]))
			}
			if v, ok := r["day"]; ok && v != nil {
				merged["day"] = v
			}
			warnings = append(warnings, s.Warn...)
		}
		merged["warnings"] = warnings
		helper.SuccessWithData(c, merged)
		return
	}

	set := wafDiscover()
	defer set.Close()
	cacheKey := strings.Join(set.Files, "|")
	wafStatMu.Lock()
	if wafStatData != nil && wafStatKey == cacheKey && time.Since(wafStatAt) < 60*time.Second {
		data := wafStatData
		wafStatMu.Unlock()
		helper.SuccessWithData(c, data)
		return
	}
	wafStatMu.Unlock()

	result := gin.H{
		"req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0,
		"total_logs": 0, "day": today, "source": "aggregated",
	}
	warnings := make([]string, 0)
	// 第一遍：waf_stat 统计表（存在时以它为准，避免与日志计数重复累加）
	hasStat := false
	for _, s := range set.Sources {
		db := set.Conns[s.Path]
		if db == nil || s.Kind != "stat" {
			continue
		}
		table := wafQI(s.Table)
		rows, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			warnings = append(warnings, filepath.Base(s.Path)+": "+err.Error())
			continue
		}
		cols, _ := rows.Columns()
		picked := map[string]interface{}(nil)
		for rows.Next() {
			values := make([]interface{}, len(cols))
			pointers := make([]interface{}, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if rows.Scan(pointers...) != nil {
				continue
			}
			row := make(map[string]interface{}, len(cols))
			for i, col := range cols {
				row[col] = wafNormalizeVal(values[i])
			}
			picked = wafPickStatRow(picked, row, today)
		}
		_ = rows.Close()
		if picked != nil {
			for _, key := range []string{"req_count", "attack_count", "count4xx", "count5xx", "day", "create_date"} {
				if v, ok := picked[key]; ok {
					result[key] = v
				}
			}
			result["source"] = "waf_stat"
			hasStat = true
		}
	}
	// 第二遍：日志/站点库聚合（统计表已提供的指标不再重复累加）
	for _, s := range set.Sources {
		db := set.Conns[s.Path]
		if db == nil {
			continue
		}
		table := wafQI(s.Table)
		if s.Kind == "log" {
			var n int
			if db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n) == nil {
				result["total_logs"] = wafToFloat(result["total_logs"]) + float64(n)
			}
			parts := make([]string, 0)
			if s.Cols["is_attack"] {
				parts = append(parts, wafQI("is_attack")+" = 1")
			}
			if s.Cols["action"] {
				parts = append(parts, wafQI("action")+" = 'deny'")
			}
			for _, col := range wafRuleCols(s.Cols) {
				if col == "rule" || col == "exec_rule" {
					parts = append(parts, "("+wafQI(col)+" IS NOT NULL AND "+wafQI(col)+" <> '')")
				}
			}
			if !hasStat && len(parts) > 0 {
				if db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+strings.Join(parts, " OR ")).Scan(&n) == nil {
					result["attack_count"] = int(wafToFloat(result["attack_count"])) + n
				}
			}
			if !hasStat {
				statusCol := ""
				for _, col := range []string{"status", "status_code"} {
					if s.Cols[col] {
						statusCol = wafQI(col)
						break
					}
				}
				if statusCol != "" {
					if db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+statusCol+" >= 400 AND "+statusCol+" < 500").Scan(&n) == nil {
						result["count4xx"] = int(wafToFloat(result["count4xx"])) + n
					}
					if db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+statusCol+" >= 500").Scan(&n) == nil {
						result["count5xx"] = int(wafToFloat(result["count5xx"])) + n
					}
				}
			}
		}
		if s.Kind == "sitelog" {
			var n int
			if db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n) == nil {
				result["total_logs"] = wafToFloat(result["total_logs"]) + float64(n)
				if !hasStat {
					result["req_count"] = int(wafToFloat(result["req_count"])) + n
				}
			}
			if hasStat {
				continue
			}
			statusCol := ""
			for _, col := range []string{"status_code", "status"} {
				if s.Cols[col] {
					statusCol = wafQI(col)
					break
				}
			}
			if statusCol != "" {
				if db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+statusCol+" >= 400 AND "+statusCol+" < 500").Scan(&n) == nil {
					result["count4xx"] = int(wafToFloat(result["count4xx"])) + n
				}
				if db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+statusCol+" >= 500").Scan(&n) == nil {
					result["count5xx"] = int(wafToFloat(result["count5xx"])) + n
				}
			}
		}
	}
	if wafToFloat(result["req_count"]) == 0 {
		result["req_count"] = int(wafToFloat(result["total_logs"]))
	}
	result["warnings"] = warnings

	wafStatMu.Lock()
	wafStatKey, wafStatAt, wafStatData = cacheKey, time.Now(), result
	wafStatMu.Unlock()
	helper.SuccessWithData(c, result)
}

// WafLogSites 网站 / 站点列表
func (b *BaseApi) WafLogSites(c *gin.Context) {
	if sets := wafV2Discover(); len(sets) > 0 {
		defer func() {
			for _, s := range sets {
				s.close()
			}
		}()
		seen := make(map[string]bool)
		list := make([]gin.H, 0, 8)
		for _, s := range sets {
			for _, v := range s.sites() {
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				list = append(list, gin.H{"website_key": v})
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i]["website_key"].(string) < list[j]["website_key"].(string)
		})
		helper.SuccessWithData(c, gin.H{"data": list})
		return
	}

	set := wafDiscover()
	defer set.Close()
	kind := c.Query("kind")
	sites := make(map[string]bool)
	for _, s := range set.Sources {
		if kind == "site" && s.Kind != "sitelog" {
			continue
		}
		if kind == "waf" && s.Kind != "log" {
			continue
		}
		if s.Kind == "log" {
			for _, col := range []string{"website_key", "server_name", "host"} {
				if !s.Cols[col] {
					continue
				}
				query := "SELECT DISTINCT " + wafQI(col) + " AS v FROM " + wafQI(s.Table) +
					" WHERE " + wafQI(col) + " IS NOT NULL AND " + wafQI(col) + " <> '' AND " + wafQI(col) + " <> 'unknown' LIMIT 500"
				rows, err := set.Conns[s.Path].Query(query)
				if err != nil {
					continue
				}
				for rows.Next() {
					var v string
					if rows.Scan(&v) == nil {
						sites[v] = true
					}
				}
				_ = rows.Close()
				break
			}
		}
		if s.Kind == "sitelog" && s.Site != "" {
			sites[s.Site] = true
		}
	}
	list := make([]gin.H, 0, len(sites))
	for v := range sites {
		list = append(list, gin.H{"website_key": v})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i]["website_key"].(string) < list[j]["website_key"].(string)
	})
	helper.SuccessWithData(c, gin.H{"data": list})
}

// WafLogRules 命中规则下拉（从数据库动态生成，兼容 v1/v2 规则名）
func (b *BaseApi) WafLogRules(c *gin.Context) {
	if sets := wafV2Discover(); len(sets) > 0 {
		defer func() {
			for _, s := range sets {
				s.close()
			}
		}()
		seen := make(map[string]bool)
		list := make([]gin.H, 0, 16)
		for _, s := range sets {
			for _, item := range s.rules() {
				k := item["value"].(string)
				if seen[k] {
					continue
				}
				seen[k] = true
				list = append(list, item)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i]["value"].(string) < list[j]["value"].(string)
		})
		helper.SuccessWithData(c, gin.H{"data": list})
		return
	}

	set := wafDiscover()
	defer set.Close()
	values := make(map[string]bool)
	for _, s := range set.Sources {
		if s.Kind != "log" {
			continue
		}
		for _, col := range wafRuleCols(s.Cols) {
			query := "SELECT DISTINCT " + wafQI(col) + " AS v FROM " + wafQI(s.Table) +
				" WHERE " + wafQI(col) + " IS NOT NULL AND " + wafQI(col) + " <> '' LIMIT 500"
			rows, err := set.Conns[s.Path].Query(query)
			if err != nil {
				continue
			}
			for rows.Next() {
				var v string
				if rows.Scan(&v) == nil && v != "" {
					values[v] = true
				}
			}
			_ = rows.Close()
		}
	}
	list := make([]gin.H, 0, len(values))
	for v := range values {
		list = append(list, gin.H{"value": v, "label": wafTranslate(v)})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i]["value"].(string) < list[j]["value"].(string)
	})
	helper.SuccessWithData(c, gin.H{"data": list})
}

// WafLogList 拦截记录
func (b *BaseApi) WafLogList(c *gin.Context) {
	f := wafParseFilters(c)
	if sets := wafV2Discover(); len(sets) > 0 {
		defer func() {
			for _, s := range sets {
				s.close()
			}
		}()
		rows := make([]map[string]interface{}, 0, f.Size*len(sets))
		total := 0
		warnings := make([]string, 0)
		for _, s := range sets {
			rs, t, w := s.list(f)
			rows = append(rows, rs...)
			total += t
			warnings = append(warnings, w...)
		}
		sort.SliceStable(rows, func(i, j int) bool {
			return wafToFloat(rows[i]["_sort"]) > wafToFloat(rows[j]["_sort"])
		})
		offset := (f.Page - 1) * f.Size
		if offset > len(rows) {
			offset = len(rows)
		}
		end := offset + f.Size
		if end > len(rows) {
			end = len(rows)
		}
		helper.SuccessWithData(c, gin.H{
			"data": rows[offset:end], "total": total,
			"page": f.Page, "size": f.Size, "warnings": warnings,
		})
		return
	}

	set := wafDiscover()
	defer set.Close()
	helper.SuccessWithData(c, wafQuery(set, "log", f, wafOutCols, true))
}

// WafLogSiteLogs 站点流量日志（1pwaf 2.0 已不再单独落 site_req_logs.db，
// 该接口仅兼容旧布局；v2 下返回空并给出说明）
func (b *BaseApi) WafLogSiteLogs(c *gin.Context) {
	f := wafParseFilters(c)
	if sets := wafV2Discover(); len(sets) > 0 {
		for _, s := range sets {
			s.close()
		}
		helper.SuccessWithData(c, gin.H{
			"data": []interface{}{}, "total": 0, "page": f.Page, "size": f.Size,
			"warnings": []string{"1pwaf 2.0 不再单独写 site_req_logs.db；站点访问日志请看「网站 → 日志」或下方 WAF 记录"},
		})
		return
	}

	set := wafDiscover()
	defer set.Close()
	helper.SuccessWithData(c, wafQuery(set, "sitelog", f, wafSiteCols, false))
}
