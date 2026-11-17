package v2

// 1Panel v2.x 社区版 WAF 日志「导出 / 清空」（补丁文件，新增）
//
// 对应官方 xpack：GET /xpack/waf/log/export、POST /xpack/waf/log/clear

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
	_ "github.com/glebarez/go-sqlite"
)

// 收集当前筛选条件下的全部日志行（上限 5000，避免导出把内存打满）
func wafCollectRows(c *gin.Context, want int) ([]map[string]interface{}, int, []string) {
	f := wafParseFilters(c)
	f.Page = 1
	f.Size = want

	if sets := wafV2Discover(); len(sets) > 0 {
		defer func() {
			for _, s := range sets {
				s.close()
			}
		}()
		rows := make([]map[string]interface{}, 0, want*len(sets))
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
		return rows, total, warnings
	}

	set := wafDiscover()
	defer set.Close()
	res := wafQuery(set, "log", f, wafOutCols, true)
	rows, _ := res["data"].([]map[string]interface{})
	total, _ := res["total"].(int)
	warnings, _ := res["warnings"].([]string)
	return rows, total, warnings
}

func wafCell(row map[string]interface{}, key string) string {
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "是"
		}
		return "否"
	case []byte:
		return string(t)
	}
	return fmt.Sprintf("%v", v)
}

// WafLogExport GET /api/v2/waf-log/log/export（沿用列表的筛选参数）
func (b *BaseApi) WafLogExport(c *gin.Context) {
	rows, total, _ := wafCollectRows(c, 5000)

	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{
		"时间", "站点", "IP", "归属地", "方法", "URI", "规则", "规则类型",
		"命中内容", "动作", "是否拦截", "状态码", "User-Agent", "原始日志",
	})
	for _, r := range rows {
		loc := wafCell(r, "ip_country_zh")
		if p := wafCell(r, "ip_province_zh"); p != "" {
			loc += " " + p
		}
		blocked := "否"
		if wafCell(r, "is_block") == "1" || wafCell(r, "is_block") == "true" {
			blocked = "是"
		}
		_ = w.Write([]string{
			wafCell(r, "localtime"), wafCell(r, "website_key"), wafCell(r, "ip"), loc,
			wafCell(r, "method"), wafCell(r, "uri"), wafCell(r, "exec_rule"), wafCell(r, "rule_type"),
			wafCell(r, "match_value"), wafCell(r, "action"), blocked,
			wafCell(r, "status_code"), wafCell(r, "user_agent"), wafCell(r, "nginx_log"),
		})
	}
	w.Flush()

	name := "waf-log.csv"
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Header("X-Waf-Export-Total", strconv.Itoa(total))
	c.String(200, "\ufeff"+sb.String())
}

// 清空日志涉及的表（全量重置，统计数字也会归零）
var wafClearTargets = []struct {
	DB    string
	Table string
}{
	{"attack_logs.db", "attack_logs"},
	{"attack_logs.db", "waf_log_outbox"},
	{"nginx_logs.db", "nginx_logs"},
	{"waf_stat.db", "waf_stat"},
	{"rule_stats.db", "rule_stats"},
	{"rule_stats.db", "processed_events"},
	{"uri_stats.db", "uri_stats"},
	{"uri_stats.db", "processed_events"},
	{"ip_stats.db", "ip_stats"},
	{"ip_stats.db", "processed_events"},
}

// WafLogClear POST /api/v2/waf-log/log/clear
func (b *BaseApi) WafLogClear(c *gin.Context) {
	dir, err := wafWafDbDir()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	deleted := make(map[string]int64, len(wafClearTargets))
	warns := make([]string, 0)
	for _, t := range wafClearTargets {
		p := filepath.Join(dir, t.DB)
		if !wafPathExists(p) {
			continue
		}
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			warns = append(warns, t.DB+" 打开失败："+err.Error())
			continue
		}
		res, err := db.Exec("DELETE FROM " + wafQI(t.Table))
		if err != nil {
			warns = append(warns, t.DB+"."+t.Table+" 清理失败："+err.Error())
			db.Close()
			continue
		}
		n, _ := res.RowsAffected()
		deleted[t.DB+"."+t.Table] = n
		db.Close()
	}
	helper.SuccessWithData(c, gin.H{
		"saved": true, "deleted": deleted, "warnings": warns,
		"hint": "攻击日志与统计已清空，拦截规则与黑白名单不受影响",
	})
}
