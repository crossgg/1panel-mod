package v2

// 1Panel v2.x 社区版 WAF「概览」API（补丁文件，新增，不修改任何现有源码）
//
// 数据来源与官方 xpack 的 /api/v2/xpack/waf/{stat,stat/days,relation/stat,locations} 同源，
// 全部来自 1pwaf/data/db 下的 SQLite：
//   waf/waf_stat.db    每日一行：day / req_count / attack_count / count4xx / count5xx
//   waf/attack_logs.db 事实表：只存 *_id 外键，需 join 维度库
//   waf/ips.db uris.db rules.db rule_types.db hosts.db    (id, value)
//   global/default.db  actions / methods                  (id, value)
//   global/location.db locations  (id, iso, country_zh, province_zh, ...)

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
)

// wafTopItem 一条排行榜数据
type wafTopItem struct {
	Value string `json:"value"`
	Count int    `json:"count"`
	Extra string `json:"extra,omitempty"`
}

// wafPair 聚合中间结果
type wafPair struct {
	ID int64
	N  int
}

func wafDayStart(t time.Time) float64 {
	y, m, d := t.Date()
	return float64(time.Date(y, m, d, 0, 0, 0, 0, t.Location()).Unix())
}

// groupCount 按 attack_logs 里的某个 id 列做分组计数（只统计 time >= since 的记录）
func (v *wafV2) groupCount(col string, since float64, limit int) []wafPair {
	db := v.db(filepath.Join(v.Base, "waf", "attack_logs.db"))
	if db == nil || !wafHasTable(db, "attack_logs") {
		return nil
	}
	// col 全部为内部常量，不接受外部输入
	q := fmt.Sprintf("SELECT %s, COUNT(*) AS c FROM attack_logs WHERE time >= ? AND %s IS NOT NULL GROUP BY %s ORDER BY c DESC LIMIT ?",
		wafQI(col), wafQI(col), wafQI(col))
	rows, err := db.Query(q, since, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]wafPair, 0, limit)
	for rows.Next() {
		var id sql.NullInt64
		var n int
		if rows.Scan(&id, &n) == nil && id.Valid {
			out = append(out, wafPair{ID: id.Int64, N: n})
		}
	}
	return out
}

// dimTop 把 id 计数翻译成维度值
func (v *wafV2) dimTop(col, dim, extraDim string, since float64, limit int) []wafTopItem {
	if limit <= 0 {
		limit = 10
	}
	pairs := v.groupCount(col, since, limit)
	out := make([]wafTopItem, 0, len(pairs))
	for _, p := range pairs {
		val := v.dimValue(dim, p.ID)
		if val == "" {
			val = "-"
		}
		extra := ""
		if extraDim != "" {
			extra = v.dimValue(extraDim, p.ID)
		}
		out = append(out, wafTopItem{Value: wafStr(wafTranslate(val)), Count: p.N, Extra: extra})
	}
	return out
}

// locTop 归属地排行（location.db 结构特殊，单独处理）
func (v *wafV2) locTop(since float64, limit int) []wafTopItem {
	pairs := v.groupCount("ip_location_id", since, limit)
	if len(pairs) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(pairs))
	for _, p := range pairs {
		ids = append(ids, p.ID)
	}
	locs := v.wafV2Locations(ids)
	out := make([]wafTopItem, 0, len(pairs))
	for _, p := range pairs {
		m := locs[p.ID]
		zh := wafStr(m["country_zh"])
		pv := wafStr(m["province_zh"])
		label := zh
		if pv != "" && pv != zh {
			label = zh + " " + pv
		}
		if label == "" {
			label = wafStr(m["country_en"])
		}
		if label == "" {
			label = "未知"
		}
		out = append(out, wafTopItem{Value: label, Count: p.N, Extra: wafStr(m["iso"])})
	}
	return out
}

// trend 最近 days 天的每日趋势（waf_stat 缺失的日期补 0）
func (v *wafV2) trend(days int) []gin.H {
	if days <= 0 {
		days = 30
	}
	byDay := make(map[string]gin.H)
	db := v.db(filepath.Join(v.Base, "waf", "waf_stat.db"))
	if db != nil && wafHasTable(db, "waf_stat") {
		cols, err := wafTableCols(db, "waf_stat")
		if err == nil {
			want := make([]string, 0, 6)
			for _, c := range []string{"day", "req_count", "attack_count", "count4xx", "count5xx"} {
				if cols[c] {
					want = append(want, c)
				}
			}
			if len(want) > 0 {
				sel := ""
				for i, w := range want {
					if i > 0 {
						sel += ", "
					}
					sel += wafQI(w)
				}
				if rows, err := db.Query("SELECT " + sel + " FROM waf_stat"); err == nil {
					for rows.Next() {
						values := make([]interface{}, len(want))
						ptrs := make([]interface{}, len(want))
						for i := range values {
							ptrs[i] = &values[i]
						}
						if rows.Scan(ptrs...) != nil {
							continue
						}
						item := gin.H{}
						for i, name := range want {
							item[name] = wafNormalizeVal(values[i])
						}
						day := wafStr(item["day"])
						if len(day) >= 10 {
							day = day[:10]
						}
						if day != "" {
							byDay[day] = item
						}
					}
					rows.Close()
				}
			}
		}
	}

	now := time.Now()
	out := make([]gin.H, 0, days)
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		if item, ok := byDay[d]; ok {
			item["day"] = d
			out = append(out, gin.H{
				"day": d,
				"req_count":    int(wafToFloat(item["req_count"])),
				"attack_count": int(wafToFloat(item["attack_count"])),
				"count4xx":     int(wafToFloat(item["count4xx"])),
				"count5xx":     int(wafToFloat(item["count5xx"])),
			})
			continue
		}
		out = append(out, gin.H{"day": d, "req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0})
	}
	return out
}

// hourly 今日 0-23 时的攻击次数分布
func (v *wafV2) hourly() []gin.H {
	out := make([]gin.H, 24)
	for h := 0; h < 24; h++ {
		out[h] = gin.H{"hour": h, "count": 0}
	}
	db := v.db(filepath.Join(v.Base, "waf", "attack_logs.db"))
	if db == nil || !wafHasTable(db, "attack_logs") {
		return out
	}
	since := wafDayStart(time.Now())
	rows, err := db.Query(
		"SELECT CAST(strftime('%H', time, 'unixepoch', 'localtime') AS INTEGER) AS h, COUNT(*) "+
			"FROM attack_logs WHERE time >= ? GROUP BY h", since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var h sql.NullInt64
		var n int
		if rows.Scan(&h, &n) == nil && h.Valid && h.Int64 >= 0 && h.Int64 < 24 {
			out[h.Int64] = gin.H{"hour": int(h.Int64), "count": n}
		}
	}
	return out
}

// statOfDay 读 waf_stat 里某一天（不存在返回 nil）
func (v *wafV2) statOfDay(day string) gin.H {
	db := v.db(filepath.Join(v.Base, "waf", "waf_stat.db"))
	if db == nil || !wafHasTable(db, "waf_stat") {
		return nil
	}
	rows, err := db.Query("SELECT day, req_count, attack_count, count4xx, count5xx FROM waf_stat WHERE day = ?", day)
	if err != nil {
		return nil
	}
	defer rows.Close()
	if rows.Next() {
		var d sql.NullString
		var req, atk, c4, c5 sql.NullInt64
		if rows.Scan(&d, &req, &atk, &c4, &c5) == nil {
			return gin.H{"day": d.String, "req_count": int(req.Int64),
				"attack_count": int(atk.Int64), "count4xx": int(c4.Int64), "count5xx": int(c5.Int64)}
		}
	}
	return nil
}

// overview 汇总一个 1pwaf 实例的概览数据
func (v *wafV2) overview(days, topN int) gin.H {
	v.loadDims()
	if topN <= 0 || topN > 50 {
		topN = 10
	}
	now := time.Now()
	today := now.Format("2006-01-02")
	yest := now.AddDate(0, 0, -1).Format("2006-01-02")
	since := wafDayStart(now)

	dayZero := gin.H{"day": today, "req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0}
	todayStat := dayZero
	if s := v.statOfDay(today); s != nil {
		todayStat = s
	}
	yestStat := gin.H{"day": yest, "req_count": 0, "attack_count": 0, "count4xx": 0, "count5xx": 0}
	if s := v.statOfDay(yest); s != nil {
		yestStat = s
	}

	res := gin.H{
		"today":     todayStat,
		"yesterday": yestStat,
		"trend":     v.trend(days),
		"hourly":    v.hourly(),
		"top_ips":      v.dimTop("ip_id", "ips", "", since, topN),
		"top_uris":     v.dimTop("uri_id", "uris", "", since, topN),
		"top_rules":    v.dimTop("rule_id", "rules", "", since, topN),
		"top_rule_types": v.dimTop("rule_type_id", "rule_types", "", since, topN),
		"top_hosts":    v.dimTop("host_id", "hosts", "", since, topN),
		"top_actions":  v.dimTop("action_id", "actions", "", since, topN),
		"top_locations": v.locTop(since, topN),
		"total_logs":  0,
	}
	// 明细总数
	if db := v.db(filepath.Join(v.Base, "waf", "attack_logs.db")); db != nil {
		var n int
		if db.QueryRow("SELECT COUNT(*) FROM attack_logs").Scan(&n) == nil {
			res["total_logs"] = n
		}
	}
	// 站点数（有域名归属的才算）
	sites := 0
	for _, val := range v.Dims["websites"] {
		if val != "" && val != "unknown" {
			sites++
		}
	}
	res["site_count"] = sites
	res["warn"] = v.Warn
	return res
}

func wafRate(part, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(int(part/total*1000+0.5)) / 10
}

// mergeTops 合并多实例的 TOP 榜（按 value 累加后重排）
func mergeTops(dsts ...[]wafTopItem) []wafTopItem {
	sum := make(map[string]*wafTopItem)
	for _, list := range dsts {
		for _, it := range list {
			if cur, ok := sum[it.Value]; ok {
				cur.Count += it.Count
				continue
			}
			c := it
			sum[it.Value] = &c
		}
	}
	out := make([]wafTopItem, 0, len(sum))
	for _, it := range sum {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Value < out[j].Value
		}
		return out[i].Count > out[j].Count
	})
	return out
}

// WafLogOverview 概览页聚合数据
func (b *BaseApi) WafLogOverview(c *gin.Context) {
	days := 30
	if s := c.Query("days"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 7 && n <= 90 {
			days = n
		}
	}
	topN := 10
	if s := c.Query("top"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 3 && n <= 50 {
			topN = n
		}
	}

	sets := wafV2Discover()
	if len(sets) == 0 {
		helper.SuccessWithData(c, gin.H{
			"ok": false, "layout": "none", "hint": "未找到 1pwaf 数据目录，请确认 OpenResty + WAF 已启用",
			"today": gin.H{}, "yesterday": gin.H{}, "trend": []gin.H{}, "hourly": []gin.H{},
		})
		return
	}
	defer func() {
		for _, s := range sets {
			s.close()
		}
	}()

	merged := gin.H{
		"ok": true, "layout": "v2-1pwaf", "today": nil, "yesterday": nil,
		"trend": []gin.H{}, "hourly": []gin.H{},
		"top_ips": []wafTopItem{}, "top_uris": []wafTopItem{}, "top_rules": []wafTopItem{},
		"top_rule_types": []wafTopItem{}, "top_hosts": []wafTopItem{},
		"top_actions": []wafTopItem{}, "top_locations": []wafTopItem{},
		"total_logs": 0, "site_count": 0, "instances": len(sets), "warnings": []string{},
	}

	var (
		todayReq, todayAtk, today4xx  int
		yestReq, yestAtk              int
		totalLogs                     int
		siteCount                     int
		trendSum                      = map[string]*[2]int{}
		hourlySum                     = map[int]int{}
		warns                         = make([]string, 0)
		ips, uris, rules, types       []wafTopItem
		hosts, actions, locs          []wafTopItem
	)

	for _, s := range sets {
		o := s.overview(days, topN)
		t, _ := o["today"].(gin.H)
		y, _ := o["yesterday"].(gin.H)
		todayReq += int(wafToFloat(t["req_count"]))
		todayAtk += int(wafToFloat(t["attack_count"]))
		today4xx += int(wafToFloat(t["count4xx"]))
		yestReq += int(wafToFloat(y["req_count"]))
		yestAtk += int(wafToFloat(y["attack_count"]))
		totalLogs += int(wafToFloat(o["total_logs"]))
		siteCount += int(wafToFloat(o["site_count"]))
		if v, ok := o["warn"].([]string); ok {
			warns = append(warns, v...)
		}
		if tr, ok := o["trend"].([]gin.H); ok {
			for _, it := range tr {
				d := wafStr(it["day"])
				cell, ok := trendSum[d]
				if !ok {
					cell = &[2]int{}
					trendSum[d] = cell
				}
				cell[0] += int(wafToFloat(it["req_count"]))
				cell[1] += int(wafToFloat(it["attack_count"]))
			}
		}
		if hr, ok := o["hourly"].([]gin.H); ok {
			for _, it := range hr {
				hourlySum[int(wafToFloat(it["hour"]))] += int(wafToFloat(it["count"]))
			}
		}
		if v, ok := o["top_ips"].([]wafTopItem); ok {
			ips = append(ips, v...)
		}
		if v, ok := o["top_uris"].([]wafTopItem); ok {
			uris = append(uris, v...)
		}
		if v, ok := o["top_rules"].([]wafTopItem); ok {
			rules = append(rules, v...)
		}
		if v, ok := o["top_rule_types"].([]wafTopItem); ok {
			types = append(types, v...)
		}
		if v, ok := o["top_hosts"].([]wafTopItem); ok {
			hosts = append(hosts, v...)
		}
		if v, ok := o["top_actions"].([]wafTopItem); ok {
			actions = append(actions, v...)
		}
		if v, ok := o["top_locations"].([]wafTopItem); ok {
			locs = append(locs, v...)
		}
	}

	// 趋势补齐并按日期排序
	now := time.Now()
	trend := make([]gin.H, 0, days)
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		cell := trendSum[d]
		req, atk := 0, 0
		if cell != nil {
			req, atk = cell[0], cell[1]
		}
		trend = append(trend, gin.H{"day": d, "req_count": req, "attack_count": atk})
	}
	hourly := make([]gin.H, 24)
	for h := 0; h < 24; h++ {
		hourly[h] = gin.H{"hour": h, "count": hourlySum[h]}
	}

	merged["today"] = gin.H{
		"day": now.Format("2006-01-02"), "req_count": todayReq, "attack_count": todayAtk,
		"count4xx": today4xx, "block_rate": wafRate(float64(todayAtk), float64(todayReq)),
	}
	merged["yesterday"] = gin.H{
		"day": now.AddDate(0, 0, -1).Format("2006-01-02"),
		"req_count": yestReq, "attack_count": yestAtk,
	}
	merged["trend"] = trend
	merged["hourly"] = hourly
	merged["top_ips"] = mergeTops(ips)
	merged["top_uris"] = mergeTops(uris)
	merged["top_rules"] = mergeTops(rules)
	merged["top_rule_types"] = mergeTops(types)
	merged["top_hosts"] = mergeTops(hosts)
	merged["top_actions"] = mergeTops(actions)
	merged["top_locations"] = mergeTops(locs)
	merged["total_logs"] = totalLogs
	merged["site_count"] = siteCount
	merged["warnings"] = warns

	helper.SuccessWithData(c, merged)
}
