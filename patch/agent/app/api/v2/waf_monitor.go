package v2

// 1Panel v2.x 社区版 WAF「网站监控」（补丁文件，新增）
//
// 数据全部来自 1pwaf 自带的监控 SQLite（<openresty>/1pwaf/data/db/monitor/<site>/）：
//   site_stat.db        site_stat(day, hour, pv, spider, ip, uv, flow, req, count4xx, count5xx)
//   site_req_logs.db    site_req_logs(ip_id, host_id, uri_id, req_uri_id, method_id, referer_id,
//                                     ua_id, spider_id, status_code_id, request_time, send_bytes,
//                                     receive_bytes, pv_tag, uv_tag, time, os_id, browser_id,
//                                     device_id, ip_location_id, iso_id, remote_port,
//                                     content_type_id, localtime, server_name_id, status_code)
//   *_stats.db          (resource_id, date, count)  date = yyyymmdd 整数
//     ip_stats  额外有 ip_location_id / iso_id → global/location.db locations 表
//   站点字典            ips/uris/req_uris/hosts/server_names/user_agents/referers/uvs (id, value)
//   全局字典            global/default.db: methods/os/browsers/devices/spiders/content_types/iso
//                       global/status_codes.db: status_codes(id, value)
//
// 开关/排除项：
//   全局 <data>/conf/monitor.json；站点 <data>/sites/<key>/monitor.json（同构）
//   写入后 nginx -s reload 才生效（wafReloadConf 与 global.json 同套路）。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------- 定位 ----------

func wafMonitorRoot() string {
	conf := wafConfDir()
	if conf == "" {
		return ""
	}
	return filepath.Join(wafDataDir(conf), "db", "monitor")
}

func wafMonitorSiteDirs() []string {
	root := wafMonitorRoot()
	if root == "" {
		return nil
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// wafMonPickV 从多实例里挑出 1pwaf 的数据根（.../1pwaf/data/db）
func wafMonPickV(vs []*wafV2) *wafV2 {
	var v *wafV2
	for _, s := range vs {
		if strings.HasSuffix(filepath.ToSlash(s.Base), "1pwaf/data/db") {
			v = s
		}
	}
	if v == nil && len(vs) > 0 {
		v = vs[0]
	}
	return v
}

// ---------- 字典 ----------

type wafMonDicts struct {
	Methods      map[int64]string
	OS           map[int64]string
	Browsers     map[int64]string
	Devices      map[int64]string
	Spiders      map[int64]string
	ContentTypes map[int64]string
	ISO          map[int64]string
	Status       map[int64]string   // status_codes: id -> "200"
	Locals       map[string]map[int64]string
	Locations    map[int64][6]string // id -> {iso, country_zh, lon, lat, province_zh, province_en}
}

func wafMonLoadDicts(v *wafV2, siteDir string) *wafMonDicts {
	d := &wafMonDicts{
		Methods:      map[int64]string{},
		OS:           map[int64]string{},
		Browsers:     map[int64]string{},
		Devices:      map[int64]string{},
		Spiders:      map[int64]string{},
		ContentTypes: map[int64]string{},
		ISO:          map[int64]string{},
		Status:       map[int64]string{},
		Locals:       map[string]map[int64]string{},
		Locations:    map[int64][6]string{},
	}
	def := filepath.Join(v.Base, "global", "default.db")
	d.Methods = v.readKV(def, "methods")
	d.OS = v.readKV(def, "os")
	d.Browsers = v.readKV(def, "browsers")
	d.Devices = v.readKV(def, "devices")
	d.Spiders = v.readKV(def, "spiders")
	d.ContentTypes = v.readKV(def, "content_types")
	d.ISO = v.readKV(def, "iso")
	d.Status = v.readKV(filepath.Join(v.Base, "global", "status_codes.db"), "status_codes")

	for _, t := range []string{"ips", "uris", "req_uris", "hosts", "server_names", "user_agents", "referers", "uvs"} {
		d.Locals[t] = v.readKV(filepath.Join(siteDir, t+".db"), t)
	}

	if db := v.db(filepath.Join(v.Base, "global", "location.db")); db != nil && wafHasTable(db, "locations") {
		rows, err := db.Query(`SELECT id, ifnull(iso,''), ifnull(country_zh,''), ifnull(longitude,''),
			ifnull(latitude,''), ifnull(province_zh,''), ifnull(province_en,'') FROM locations`)
		if err == nil {
			for rows.Next() {
				var id int64
				var iso, cz, lon, lat, pz, pe string
				if rows.Scan(&id, &iso, &cz, &lon, &lat, &pz, &pe) == nil {
					d.Locations[id] = [6]string{iso, cz, lon, lat, pz, pe}
				}
			}
			rows.Close()
		}
	}
	return d
}

func (d *wafMonDicts) name(table string, id int64) string {
	if m, ok := d.Locals[table]; ok {
		if s := m[id]; s != "" {
			return s
		}
	}
	switch table {
	case "methods":
		return d.Methods[id]
	case "os":
		return d.OS[id]
	case "browsers":
		return d.Browsers[id]
	case "devices":
		return d.Devices[id]
	case "spiders":
		return d.Spiders[id]
	case "content_types":
		return d.ContentTypes[id]
	case "iso":
		return d.ISO[id]
	case "status_codes":
		return d.Status[id]
	}
	return ""
}

// status_code 列恒为 0，真实状态码在 status_code_id → global/status_codes.db
func (d *wafMonDicts) statusCode(id int64) int {
	n, err := strconv.Atoi(d.Status[id])
	if err != nil {
		return 0
	}
	return n
}

// ---------- 配置 ----------

type wafMonExclude struct {
	Extensions []string      `json:"extensions"`
	Status     []interface{} `json:"status"` // 前端 allow-create 会塞字符串，这里刻意用 interface{} 容错
	URI        []string      `json:"uri"`
	UA         []string      `json:"ua"`
	IP         []string      `json:"ip"`
}

// 写盘时必须是数字数组（1pwaf 按 int 读），把前端手输的字符串统一转成 int
type wafMonExcludeOut struct {
	Extensions []string `json:"extensions"`
	Status     []int    `json:"status"`
	URI        []string `json:"uri"`
	UA         []string `json:"ua"`
	IP         []string `json:"ip"`
}

type wafMonCfgOut struct {
	State   string           `json:"state"`
	Exclude wafMonExcludeOut `json:"exclude"`
	Log     wafMonLog        `json:"log"`
}

func wafIntAny(v interface{}) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		return n, err == nil
	}
	return 0, false
}

type wafMonLog struct {
	MaxDay  int `json:"maxDay"`
	MaxSize int `json:"maxSize"`
}

type wafMonCfg struct {
	State   string        `json:"state"`
	Exclude wafMonExclude `json:"exclude"`
	Log     wafMonLog     `json:"log"`
}

func wafMonCfgPath(site string) string {
	conf := wafConfDir()
	if conf == "" {
		return ""
	}
	data := wafDataDir(conf)
	if site == "" {
		return filepath.Join(data, "conf", "monitor.json")
	}
	return filepath.Join(data, "sites", site, "monitor.json")
}

// wafMonCfgRead 读配置；站点没有自己的配置时回退全局并标注来源
func wafMonCfgRead(site string) (*wafMonCfg, string) {
	p := wafMonCfgPath(site)
	if p == "" {
		return nil, ""
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if site != "" {
			if g, _ := wafMonCfgRead(""); g != nil {
				return g, "global"
			}
		}
		return &wafMonCfg{State: "off"}, "default"
	}
	cfg := &wafMonCfg{}
	_ = json.Unmarshal(raw, cfg)
	return cfg, "self"
}

func wafMonCfgWrite(site string, cfg *wafMonCfg) error {
	p := wafMonCfgPath(site)
	if p == "" {
		return fmt.Errorf("未找到 1pwaf 数据目录")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	_, _ = wafBackupFile(p)
	out := wafMonCfgOut{
		State: cfg.State,
		Exclude: wafMonExcludeOut{
			Extensions: cfg.Exclude.Extensions,
			Status:     make([]int, 0, len(cfg.Exclude.Status)),
			URI:        cfg.Exclude.URI,
			UA:         cfg.Exclude.UA,
			IP:         cfg.Exclude.IP,
		},
		Log: cfg.Log,
	}
	for _, v := range cfg.Exclude.Status {
		if n, ok := wafIntAny(v); ok {
			out.Exclude.Status = append(out.Exclude.Status, n)
		}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ---------- 接口 ----------

// WafMonitorSites GET /waf-log/monitor/sites
func (b *BaseApi) WafMonitorSites(c *gin.Context) {
	root := wafMonitorRoot()
	if root == "" {
		wafFailErr(c, fmt.Errorf("没找到 1pwaf 的数据目录"))
		return
	}
	g, _ := wafMonCfgRead("")
	out := make([]gin.H, 0, 8)
	for _, key := range wafMonitorSiteDirs() {
		dir := filepath.Join(root, key)
		item := gin.H{"key": key}
		if cfg, src := wafMonCfgRead(key); cfg != nil {
			item["state"] = cfg.State
			item["state_from"] = src
		} else {
			item["state"] = g.State
			item["state_from"] = "global"
		}
		db, _ := wafOpenRO(filepath.Join(dir, "site_req_logs.db"))
		if db != nil {
			var n int64
			var last sql.NullFloat64
			_ = db.QueryRow("SELECT COUNT(*), MAX(time) FROM site_req_logs").Scan(&n, &last)
			item["requests"] = n
			if last.Valid && last.Float64 > 0 {
				item["last_time"] = time.Unix(int64(last.Float64), 0).Format("2006-01-02 15:04:05")
			}
			_ = db.Close()
		} else {
			item["requests"] = 0
		}
		out = append(out, item)
	}
	wafOK(c, gin.H{"global": g, "sites": out})
}

// WafMonitorOverview GET /waf-log/monitor/overview?site=&days=30
func (b *BaseApi) WafMonitorOverview(c *gin.Context) {
	site := c.Query("site")
	days := wafAtoiDefault(c.Query("days"), 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	root := wafMonitorRoot()
	dir := filepath.Join(root, site)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		wafOK(c, gin.H{"no_data": true, "site": site})
		return
	}
	vs := wafV2Discover()
	defer func() {
		for _, s := range vs {
			s.close()
		}
	}()
	v := wafMonPickV(vs)
	if v == nil {
		wafOK(c, gin.H{"no_data": true, "site": site})
		return
	}
	dicts := wafMonLoadDicts(v, dir)

	// ---- 今日汇总（site_stat 优先，空则从 site_req_logs 现算）----
	today := time.Now().Format("2006-01-02")
	sum := map[string]int64{"pv": 0, "uv": 0, "ip": 0, "req": 0, "flow": 0, "spider": 0, "count4xx": 0, "count5xx": 0}
	hours := make([]gin.H, 0, 24)
	db := v.db(filepath.Join(dir, "site_stat.db"))
	haveStat := false
	if db != nil && wafHasTable(db, "site_stat") {
		rows, err := db.Query(`SELECT hour, ifnull(sum(pv),0), ifnull(sum(uv),0), ifnull(sum(ip),0), ifnull(sum(req),0),
			ifnull(sum(flow),0), ifnull(sum(spider),0), ifnull(sum(count4xx),0), ifnull(sum(count5xx),0)
			FROM site_stat WHERE day = ? GROUP BY hour ORDER BY hour`, today)
		if err == nil {
			for rows.Next() {
				var hour string
				var pv, uv, ip, req, flow, sp, c4, c5 int64
				if rows.Scan(&hour, &pv, &uv, &ip, &req, &flow, &sp, &c4, &c5) == nil {
					haveStat = true
					hours = append(hours, gin.H{"hour": hour, "pv": pv, "uv": uv, "ip": ip, "req": req,
						"flow": flow, "spider": sp, "count4xx": c4, "count5xx": c5})
					sum["pv"] += pv
					sum["uv"] += uv
					sum["ip"] += ip
					sum["req"] += req
					sum["flow"] += flow
					sum["spider"] += sp
					sum["count4xx"] += c4
					sum["count5xx"] += c5
				}
			}
			rows.Close()
		}
	}

	// ---- 实时（最近 60s）----
	realtime := gin.H{"req": int64(0), "flow": int64(0), "window": 60}
	if logDB := v.db(filepath.Join(dir, "site_req_logs.db")); logDB != nil && wafHasTable(logDB, "site_req_logs") {
		var req int64
		var flow sql.NullInt64
		since := float64(time.Now().Unix() - 60)
		_ = logDB.QueryRow(`SELECT COUNT(*), ifnull(sum(send_bytes+receive_bytes),0) FROM site_req_logs WHERE time >= ?`, since).Scan(&req, &flow)
		realtime["req"] = req
		realtime["flow"] = flow.Int64

		if !haveStat {
			// 回退：今日全量从明细表算
			now := time.Now()
			dayStart := float64(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix())
			var pv, fl sql.NullInt64
			if err := logDB.QueryRow(`SELECT COUNT(*), ifnull(sum(send_bytes+receive_bytes),0)
				FROM site_req_logs WHERE time >= ?`, dayStart).Scan(&pv, &fl); err == nil {
				sum["req"], sum["pv"] = pv.Int64, pv.Int64
				sum["flow"] = fl.Int64
			}
			if rows, err := logDB.Query(`SELECT status_code_id, COUNT(*) FROM site_req_logs WHERE time >= ? GROUP BY status_code_id`, dayStart); err == nil {
				for rows.Next() {
					var id, cnt int64
					if rows.Scan(&id, &cnt) == nil {
						code := dicts.statusCode(id)
						if code >= 400 && code < 500 {
							sum["count4xx"] += cnt
						} else if code >= 500 {
							sum["count5xx"] += cnt
						}
					}
				}
				rows.Close()
			}
		}
	}

	// ---- 访客地图（近 N 天）：ip_stats ⨝ locations ----
	countries := make([]gin.H, 0, 16)
	provinces := make([]gin.H, 0, 40)
	dateFrom, _ := strconv.Atoi(time.Now().AddDate(0, 0, -days+1).Format("20060102"))
	ipsDB := v.db(filepath.Join(dir, "ip_stats.db"))
	if ipsDB != nil && wafHasTable(ipsDB, "ip_stats") {
		rows, err := ipsDB.Query(`SELECT ifnull(ip_location_id,0), ifnull(iso_id,0), ifnull(sum(count),0)
			FROM ip_stats WHERE date >= ? GROUP BY ip_location_id, iso_id`, dateFrom)
		if err == nil {
			type aggr struct {
				iso, name string
				count     int64
				lon, lat  float64
			}
			byKey := map[string]*aggr{}
			byProv := map[string]*aggr{}
			for rows.Next() {
				var locID, isoID, cnt int64
				if rows.Scan(&locID, &isoID, &cnt) != nil {
					continue
				}
				loc := dicts.Locations[locID]
				iso := loc[0]
				if iso == "" {
					iso = dicts.ISO[isoID]
				}
				name := loc[1]
				if iso == "" && name == "" {
					continue
				}
				if name == "" {
					name = iso
				}
				k := iso + "/" + name
				a := byKey[k]
				if a == nil {
					a = &aggr{iso: iso, name: name}
					byKey[k] = a
				}
				a.count += cnt
				if a.lon == 0 && a.lat == 0 {
					a.lon, _ = strconv.ParseFloat(loc[2], 64)
					a.lat, _ = strconv.ParseFloat(loc[3], 64)
				}
				if iso == "CN" && (loc[4] != "" || loc[5] != "") {
					pn := loc[4]
					if pn == "" {
						pn = loc[5]
					}
					p := byProv[pn]
					if p == nil {
						p = &aggr{name: pn}
						byProv[pn] = p
					}
					p.count += cnt
					p.lon, _ = strconv.ParseFloat(loc[2], 64)
					p.lat, _ = strconv.ParseFloat(loc[3], 64)
				}
			}
			rows.Close()
			for _, p := range byProv {
				provinces = append(provinces, gin.H{"name": p.name, "name_en": p.name, "count": p.count, "lon": p.lon, "lat": p.lat})
			}
			for _, a := range byKey {
				if a.iso == "LOCAL" {
					continue
				}
				countries = append(countries, gin.H{"iso": a.iso, "name": a.name, "count": a.count, "lon": a.lon, "lat": a.lat})
			}
		}
	}
	sort.SliceStable(countries, func(i, j int) bool {
		return countries[i]["count"].(int64) > countries[j]["count"].(int64)
	})
	sort.SliceStable(provinces, func(i, j int) bool {
		return provinces[i]["count"].(int64) > provinces[j]["count"].(int64)
	})

	wafOK(c, gin.H{
		"site":      site,
		"days":      days,
		"today":     today,
		"sum":       sum,
		"hours":     hours,
		"realtime":  realtime,
		"countries": countries,
		"provinces": provinces,
		"stat_mode": map[bool]string{true: "site_stat", false: "req_logs"}[haveStat],
	})
}

// WafMonitorTrend GET /waf-log/monitor/trend?site=&days=30&gran=day|hour
func (b *BaseApi) WafMonitorTrend(c *gin.Context) {
	site := c.Query("site")
	gran := c.Query("gran")
	if gran != "hour" {
		gran = "day"
	}
	days := wafAtoiDefault(c.Query("days"), 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	root := wafMonitorRoot()
	db, _ := wafOpenRO(filepath.Join(root, site, "site_stat.db"))
	if db == nil || !wafHasTable(db, "site_stat") {
		wafOK(c, gin.H{"gran": gran, "rows": []gin.H{}})
		return
	}
	defer db.Close()
	day := time.Now().AddDate(0, 0, -days+1).Format("2006-01-02")
	q := `SELECT day, hour, ifnull(sum(pv),0), ifnull(sum(uv),0), ifnull(sum(ip),0), ifnull(sum(req),0),
		ifnull(sum(flow),0), ifnull(sum(spider),0), ifnull(sum(count4xx),0), ifnull(sum(count5xx),0)
		FROM site_stat WHERE day >= ?`
	group := " GROUP BY day, hour ORDER BY day, hour"
	if gran == "day" {
		q = `SELECT day, '', ifnull(sum(pv),0), ifnull(sum(uv),0), ifnull(sum(ip),0), ifnull(sum(req),0),
		ifnull(sum(flow),0), ifnull(sum(spider),0), ifnull(sum(count4xx),0), ifnull(sum(count5xx),0)
		FROM site_stat WHERE day >= ?`
		group = " GROUP BY day ORDER BY day"
	}
	rows, err := db.Query(q+group, day)
	if err != nil {
		wafOK(c, gin.H{"gran": gran, "rows": []gin.H{}})
		return
	}
	defer rows.Close()
	out := make([]gin.H, 0, 64)
	for rows.Next() {
		var d, hour string
		var pv, uv, ip, req, flow, sp, c4, c5 int64
		if rows.Scan(&d, &hour, &pv, &uv, &ip, &req, &flow, &sp, &c4, &c5) == nil {
			out = append(out, gin.H{"day": d, "hour": hour, "pv": pv, "uv": uv, "ip": ip, "req": req,
				"flow": flow, "spider": sp, "count4xx": c4, "count5xx": c5})
		}
	}
	wafOK(c, gin.H{"gran": gran, "rows": out})
}

// ---------- 维度 TOP ----------

type wafDimItem struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func wafDimTop(db *sql.DB, table string, dateFrom int, dicts *wafMonDicts, dictTable string, top int) []wafDimItem {
	out := make([]wafDimItem, 0, top)
	if db == nil || !wafHasTable(db, table) {
		return out
	}
	q := "SELECT resource_id, ifnull(sum(count),0) FROM " + wafQI(table)
	args := make([]interface{}, 0, 1)
	if dateFrom > 0 {
		q += " WHERE date >= ?"
		args = append(args, dateFrom)
	}
	q += " GROUP BY resource_id ORDER BY 2 DESC LIMIT " + strconv.Itoa(top)
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, cnt int64
		if rows.Scan(&id, &cnt) != nil {
			continue
		}
		name := dicts.name(dictTable, id)
		if name == "" {
			name = "#" + strconv.FormatInt(id, 10)
		}
		out = append(out, wafDimItem{Name: name, Count: cnt})
	}
	return out
}

// 1pwaf 在这台机上不写 os/browser/device/referer 的 *_stats 表，
// 但明细表里有对应的 *_id，所以这里从 site_req_logs 现算
func wafDimFromLogs(db *sql.DB, col, dictTable string, since float64, dicts *wafMonDicts, top int) []wafDimItem {
	out := make([]wafDimItem, 0, top)
	if db == nil {
		return out
	}
	rows, err := db.Query(`SELECT `+col+`, COUNT(*) FROM site_req_logs WHERE time >= ? AND `+col+` > 0 GROUP BY `+col+` ORDER BY 2 DESC LIMIT `+strconv.Itoa(top), since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, cnt int64
		if rows.Scan(&id, &cnt) == nil {
			name := dicts.name(dictTable, id)
			if name == "" {
				name = "#" + strconv.FormatInt(id, 10)
			}
			out = append(out, wafDimItem{Name: name, Count: cnt})
		}
	}
	return out
}

// WafMonitorDims GET /waf-log/monitor/dims?site=&days=30
func (b *BaseApi) WafMonitorDims(c *gin.Context) {
	site := c.Query("site")
	days := wafAtoiDefault(c.Query("days"), 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	root := wafMonitorRoot()
	dir := filepath.Join(root, site)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		wafOK(c, gin.H{"no_data": true, "days": days})
		return
	}
	vs := wafV2Discover()
	defer func() {
		for _, s := range vs {
			s.close()
		}
	}()
	v := wafMonPickV(vs)
	if v == nil {
		wafOK(c, gin.H{"no_data": true, "days": days})
		return
	}
	dicts := wafMonLoadDicts(v, dir)
	dateFrom, _ := strconv.Atoi(time.Now().AddDate(0, 0, -days+1).Format("20060102"))

	open := func(name string) *sql.DB { return v.db(filepath.Join(dir, name)) }

	res := gin.H{
		"status":   wafDimTop(open("status_code_stats.db"), "status_code_stats", dateFrom, dicts, "status_codes", 10),
		"os":       wafDimTop(open("os_stats.db"), "os_stats", dateFrom, dicts, "os", 10),
		"browser":  wafDimTop(open("browser_stats.db"), "browser_stats", dateFrom, dicts, "browsers", 10),
		"device":   wafDimTop(open("device_stats.db"), "device_stats", dateFrom, dicts, "devices", 10),
		"referer":  wafDimTop(open("referer_stats.db"), "referer_stats", dateFrom, dicts, "referers", 10),
		"uri":      wafDimTop(open("uri_stats.db"), "uri_stats", dateFrom, dicts, "uris", 10),
		"ip":       wafDimTop(open("ip_stats.db"), "ip_stats", dateFrom, dicts, "ips", 10),
		"spider":   []wafDimItem{},
		"method":   []wafDimItem{},
		"contents": []wafDimItem{},
	}

	// 空 stats 表 / 没有 stats 表的维度，统一从明细表聚合
	if logDB := v.db(filepath.Join(dir, "site_req_logs.db")); logDB != nil && wafHasTable(logDB, "site_req_logs") {
		since := float64(time.Now().Unix() - int64(days)*86400)
		for _, p := range []struct{ col, dictTable, key string }{
			{"os_id", "os", "os"},
			{"browser_id", "browsers", "browser"},
			{"device_id", "devices", "device"},
			{"referer_id", "referers", "referer"},
		} {
			if len(res[p.key].([]wafDimItem)) == 0 {
				res[p.key] = wafDimFromLogs(logDB, p.col, p.dictTable, since, dicts, 10)
			}
		}
		pairs := []struct{ dictTable, col, key string }{
			{"spiders", "spider_id", "spider"},
			{"methods", "method_id", "method"},
			{"content_types", "content_type_id", "contents"},
		}
		for _, p := range pairs {
			q := "SELECT " + p.col + ", COUNT(*) FROM site_req_logs WHERE time >= ? AND " + p.col + " > 0 GROUP BY " + p.col + " ORDER BY 2 DESC LIMIT 10"
			rows, err := logDB.Query(q, since)
			if err != nil {
				continue
			}
			items := make([]wafDimItem, 0, 10)
			for rows.Next() {
				var id, cnt int64
				if rows.Scan(&id, &cnt) == nil {
					name := dicts.name(p.dictTable, id)
					if name == "" {
						name = "#" + strconv.FormatInt(id, 10)
					}
					items = append(items, wafDimItem{Name: name, Count: cnt})
				}
			}
			rows.Close()
			res[p.key] = items
		}
	}

	wafOK(c, gin.H{"days": days, "dims": res})
}

// ---------- 请求日志 ----------

// ips / uris / methods 等字典都在【别的 .db 文件】里，SQLite 单连接不能跨库子查询。
// 所以先把字典读进内存，把筛选条件翻译成 id 列表再拼 IN (...)。
func wafIdsMatch(m map[int64]string, kw string, exact bool) []int64 {
	out := make([]int64, 0, 8)
	if kw == "" {
		return out
	}
	k := strings.ToLower(kw)
	for id, v := range m {
		val := strings.ToLower(v)
		if (exact && val == k) || (!exact && strings.Contains(val, k)) {
			out = append(out, id)
		}
	}
	return out
}

// wafInClause 是 waf_log.go 里已有的（返回 sql + args），空列表会返回空串导致筛选失效，
// 这里包一层：无命中时强制 1=0。
func wafInOrZero(col string, ids []int64) (string, []interface{}) {
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	return wafInClause(col, ids)
}

func wafIdsUnion(a, b []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(a)+len(b))
	for _, id := range append(append([]int64{}, a...), b...) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// WafMonitorLogs GET /waf-log/monitor/logs?site=&page=1&size=20&ip=&uri=&status=&method=
func (b *BaseApi) WafMonitorLogs(c *gin.Context) {
	site := c.Query("site")
	page := wafAtoiDefault(c.Query("page"), 1)
	size := wafAtoiDefault(c.Query("size"), 20)
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 20
	}
	root := wafMonitorRoot()
	dir := filepath.Join(root, site)
	vs := wafV2Discover()
	defer func() {
		for _, s := range vs {
			s.close()
		}
	}()
	v := wafMonPickV(vs)
	if v == nil {
		wafOK(c, gin.H{"rows": []gin.H{}, "total": 0})
		return
	}
	dicts := wafMonLoadDicts(v, dir)
	logDB := v.db(filepath.Join(dir, "site_req_logs.db"))
	if logDB == nil || !wafHasTable(logDB, "site_req_logs") {
		wafOK(c, gin.H{"rows": []gin.H{}, "total": 0})
		return
	}

	where := make([]string, 0, 4)
	args := make([]interface{}, 0, 8)
	if s := c.Query("ip"); s != "" {
		q, a := wafInOrZero("ip_id", wafIdsMatch(dicts.Locals["ips"], s, false))
		where = append(where, q)
		args = append(args, a...)
	}
	if s := c.Query("uri"); s != "" {
		ids := wafIdsUnion(wafIdsMatch(dicts.Locals["uris"], s, false), wafIdsMatch(dicts.Locals["req_uris"], s, false))
		q1, a1 := wafInOrZero("uri_id", ids)
		q2, a2 := wafInOrZero("req_uri_id", ids)
		where = append(where, "("+q1+" OR "+q2+")")
		args = append(args, a1...)
		args = append(args, a2...)
	}
	if s := c.Query("status"); s != "" {
		ids := make([]int64, 0, 4)
		want := wafAtoiDefault(s, 0)
		for id, v := range dicts.Status {
			if n, err := strconv.Atoi(v); err == nil && n == want {
				ids = append(ids, id)
			}
		}
		q, a := wafInOrZero("status_code_id", ids)
		where = append(where, q)
		args = append(args, a...)
	}
	if s := c.Query("method"); s != "" {
		q, a := wafInOrZero("method_id", wafIdsMatch(dicts.Methods, s, true))
		where = append(where, q)
		args = append(args, a...)
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	_ = logDB.QueryRow("SELECT COUNT(*) FROM site_req_logs"+w, args...).Scan(&total)

	q := `SELECT id, ip_id, uri_id, req_uri_id, method_id, ua_id, spider_id, status_code_id, request_time,
		send_bytes, receive_bytes, time, localtime, os_id, browser_id, device_id, server_name_id, referer_id
		FROM site_req_logs` + w + " ORDER BY id DESC LIMIT " + strconv.Itoa(size) + " OFFSET " + strconv.Itoa((page-1)*size)
	rows, err := logDB.Query(q, args...)
	if err != nil {
		wafOK(c, gin.H{"rows": []gin.H{}, "total": total})
		return
	}
	defer rows.Close()
	out := make([]gin.H, 0, size)
	skip := 0
	var scanErr string
	for rows.Next() {
		var id, ipID, uriID, reqURIID, methodID, uaID, spiderID int64
		var statusCode, osID, browserID, deviceID, serverID, refererID int64
		var reqTime, sendBytes, recvBytes int64
		var t float64
		var localtime sql.NullString
		if err := rows.Scan(&id, &ipID, &uriID, &reqURIID, &methodID, &uaID, &spiderID, &statusCode, &reqTime,
			&sendBytes, &recvBytes, &t, &localtime, &osID, &browserID, &deviceID, &serverID, &refererID); err != nil {
			skip++
			if scanErr == "" {
				scanErr = err.Error()
			}
			continue
		}
		uri := dicts.name("req_uris", reqURIID)
		if uri == "" {
			uri = dicts.name("uris", uriID)
		}
		lt := localtime.String
		if lt2, err := time.Parse("2006-01-02T15:04:05Z", lt); err == nil {
			lt = lt2.Local().Format("2006-01-02 15:04:05")
		} else if lt2, err := time.Parse(time.RFC3339, lt); err == nil {
			lt = lt2.Local().Format("2006-01-02 15:04:05")
		}
		out = append(out, gin.H{
			"id":           id,
			"ip":           dicts.name("ips", ipID),
			"uri":          uri,
			"method":       dicts.name("methods", methodID),
			"ua":           dicts.name("user_agents", uaID),
			"spider":       dicts.name("spiders", spiderID),
			"status":       dicts.statusCode(statusCode),
			"request_time": reqTime,
			"send_bytes":   sendBytes,
			"recv_bytes":   recvBytes,
			"time":         int64(t),
			"localtime":    lt,
			"os":           dicts.name("os", osID),
			"browser":      dicts.name("browsers", browserID),
			"device":       dicts.name("devices", deviceID),
			"server_name":  dicts.name("server_names", serverID),
			"referer":      dicts.name("referers", refererID),
		})
	}
	wafOK(c, gin.H{"rows": out, "total": total, "page": page, "size": size, "skipped": skip, "scan_err": scanErr})
}


// WafMonitorRealtime GET /waf-log/monitor/realtime?site=&window=60
// 只开 site_req_logs.db 一个连接，供前端 5 秒轮询，避免每次重开 17 个库 + 重建图表。
func (b *BaseApi) WafMonitorRealtime(c *gin.Context) {
	site := c.Query("site")
	window := wafAtoiDefault(c.Query("window"), 60)
	if window < 5 || window > 3600 {
		window = 60
	}
	db, _ := wafOpenRO(filepath.Join(wafMonitorRoot(), site, "site_req_logs.db"))
	if db == nil || !wafHasTable(db, "site_req_logs") {
		wafOK(c, gin.H{"site": site, "req": 0, "flow": 0, "window": window})
		return
	}
	defer db.Close()
	var req int64
	var flow sql.NullInt64
	since := float64(time.Now().Unix() - int64(window))
	if err := db.QueryRow(`SELECT COUNT(*), ifnull(sum(send_bytes+receive_bytes),0) FROM site_req_logs WHERE time >= ?`, since).Scan(&req, &flow); err != nil {
		req, flow.Int64 = 0, 0
	}
	wafOK(c, gin.H{"site": site, "req": req, "flow": flow.Int64, "window": window})
}

// ---------- 配置接口 ----------

// WafMonitorConfig GET /waf-log/monitor/config?site=
func (b *BaseApi) WafMonitorConfig(c *gin.Context) {
	site := c.Query("site")
	cfg, src := wafMonCfgRead(site)
	wafOK(c, gin.H{"site": site, "from": src, "config": cfg})
}

type wafMonCfgReq struct {
	Site   string    `json:"site"`
	Config wafMonCfg `json:"config"`
}

// WafMonitorConfigSave POST /waf-log/monitor/config
func (b *BaseApi) WafMonitorConfigSave(c *gin.Context) {
	var req wafMonCfgReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafFailErr(c, err)
		return
	}
	if req.Config.State == "" {
		req.Config.State = "off"
	}
	if err := wafMonCfgWrite(req.Site, &req.Config); err != nil {
		wafFailErr(c, err)
		return
	}
	reloaded, warns, err := wafReloadConf()
	if err != nil {
		wafFailErr(c, fmt.Errorf("配置已写入，但 reload 失败: %v", err))
		return
	}
	wafOK(c, gin.H{"site": req.Site, "reloaded": reloaded, "warnings": warns})
}

// WafMonitorState POST /waf-log/monitor/state {site, state}
func (b *BaseApi) WafMonitorState(c *gin.Context) {
	var req struct {
		Site  string `json:"site"`
		State string `json:"state"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		wafFailErr(c, err)
		return
	}
	if req.State != "on" && req.State != "off" {
		wafFailErr(c, fmt.Errorf("state 只能是 on/off"))
		return
	}
	cfg, _ := wafMonCfgRead(req.Site)
	if cfg == nil {
		cfg = &wafMonCfg{}
	}
	cfg.State = req.State
	if err := wafMonCfgWrite(req.Site, cfg); err != nil {
		wafFailErr(c, err)
		return
	}
	reloaded, warns, err := wafReloadConf()
	if err != nil {
		wafFailErr(c, fmt.Errorf("开关已写入，但 reload 失败: %v", err))
		return
	}
	wafOK(c, gin.H{"site": req.Site, "state": req.State, "reloaded": reloaded, "warnings": warns})
}
