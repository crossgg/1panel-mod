package v2

// 1Panel v2.x 社区版 WAF「拦截地图（近 N 天）」（补丁文件，新增）
//
// attack_logs 只存 ip_id / ip_location_id 外键，而 location.db 在内网测试环境下
// 往往只有一行 LOCAL，无法直接给出经纬度。所以这里改用 IP 维度表拿到真实 IP，
// 再用 data/geo/GeoIP.mmdb 现场解析国家/省份/经纬度，按国家聚合。
//
// 返回结构（前端用 ECharts world 底图 + effectScatter）：
//   { days, total, blocked, countries:[{iso,name,name_en,count,lat,lon}],
//     provinces:[{name,count,lat,lon}], unknown:{count} }

import (
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
)

type wafMapPoint struct {
	Iso     string  `json:"iso"`
	Name    string  `json:"name"`
	NameEn  string  `json:"name_en"`
	Count   int     `json:"count"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Private bool    `json:"private"`
}

type wafMapProvince struct {
	Name  string  `json:"name"`
	Count int     `json:"count"`
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

// wafGeoLookup 打开 GeoIP.mmdb（打不开就算了，前端会退化成只显示 IP 数）
func wafGeoLookup() *maxminddb.Reader {
	conf := wafConfDir()
	if conf == "" {
		return nil
	}
	p := filepath.Join(wafDataDir(conf), "geo", "GeoIP.mmdb")
	r, err := maxminddb.Open(p)
	if err != nil {
		return nil
	}
	return r
}

// wafAttackMap WafAttackMap GET /api/v2/waf-log/overview/map?days=30
func (b *BaseApi) WafAttackMap(c *gin.Context) {
	days := wafAtoiDefault(c.Query("days"), 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	since := float64(time.Now().Unix() - int64(days)*86400)

	geo := wafGeoLookup()
	if geo != nil {
		defer geo.Close()
	}

	total, blocked, unknown := 0, 0, 0
	byISO := make(map[string]*wafMapPoint)
	byProv := make(map[string]*wafMapProvince)
	sites := make(map[string]int)
	ipCache := make(map[string]string) // ip → "iso|country_zh|country_en|lat|lon|prov"

	sets := wafV2Discover()
	defer func() {
		for _, s := range sets {
			s.close()
		}
	}()

	for _, v := range sets {
		db := v.db(filepath.Join(v.Base, "waf", "attack_logs.db"))
		if db == nil || !wafHasTable(db, "attack_logs") {
			continue
		}
		v.loadDims()
		ips := v.Dims["ips"]

		q := "SELECT ip_id, host_id, is_block, COUNT(*) AS c FROM attack_logs WHERE time >= ? GROUP BY ip_id, host_id, is_block"
		rows, err := db.Query(q, since)
		if err != nil {
			continue
		}
		type rec struct {
			ipID, hostID, blocked int64
			n                     int
		}
		recs := make([]rec, 0, 256)
		for rows.Next() {
			var ipID, hostID, isBlock sql.NullInt64
			var n int
			if rows.Scan(&ipID, &hostID, &isBlock, &n) == nil {
				recs = append(recs, rec{ipID.Int64, hostID.Int64, isBlock.Int64, n})
			}
		}
		rows.Close()

		for _, r := range recs {
			total += r.n
			if r.blocked > 0 {
				blocked += r.n
			}
			host := wafStr(v.dimValue("hosts", r.hostID))
			if host != "" {
				sites[host] += r.n
			}
			ipStr := wafStr(ips[r.ipID])
			if ipStr == "" {
				unknown += r.n
				continue
			}
			info, ok := ipCache[ipStr]
			if !ok {
				info = wafGeoResolve(geo, ipStr)
				ipCache[ipStr] = info
			}
			parts := strings.Split(info, "|")
			if len(parts) < 7 {
				unknown += r.n
				continue
			}
			iso, zh, en, prov, lat, lon := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
			isPrivate := parts[6] == "1"
			key := iso
			if key == "" {
				key = "??"
			}
			if p, hit := byISO[key]; hit {
				p.Count += r.n
			} else {
				pt := &wafMapPoint{Iso: iso, Name: zh, NameEn: en, Count: r.n, Private: isPrivate}
				pt.Lat, pt.Lon = wafAtof(lat), wafAtof(lon)
				if pt.Name == "" {
					pt.Name = en
				}
				byISO[key] = pt
			}
			if prov != "" && !isPrivate {
				if p, hit := byProv[prov]; hit {
					p.Count += r.n
				} else {
					byProv[prov] = &wafMapProvince{Name: prov, Count: r.n, Lat: wafAtof(lat), Lon: wafAtof(lon)}
				}
			}
		}
	}

	countries := make([]*wafMapPoint, 0, len(byISO))
	for _, p := range byISO {
		countries = append(countries, p)
	}
	sort.SliceStable(countries, func(i, j int) bool { return countries[i].Count > countries[j].Count })
	if len(countries) > 60 {
		countries = countries[:60]
	}
	provinces := make([]*wafMapProvince, 0, len(byProv))
	for _, p := range byProv {
		provinces = append(provinces, p)
	}
	sort.SliceStable(provinces, func(i, j int) bool { return provinces[i].Count > provinces[j].Count })
	if len(provinces) > 40 {
		provinces = provinces[:40]
	}
	siteList := make([]gin.H, 0, len(sites))
	for h, n := range sites {
		siteList = append(siteList, gin.H{"host": h, "count": n})
	}
	sort.SliceStable(siteList, func(i, j int) bool {
		return siteList[i]["count"].(int) > siteList[j]["count"].(int)
	})

	wafOKData(c, gin.H{
		"ok": true, "days": days, "total": total, "blocked": blocked,
		"countries": countries, "provinces": provinces, "sites": siteList,
		"unknown": unknown, "geo_ready": geo != nil,
		"hint": "经纬度来自 data/geo/GeoIP.mmdb；点大小按拦截次数加权",
	})
}

// wafGeoResolve 返回 "iso|国家中文|国家英文|省份|纬度|经度|是否内网"
func wafGeoResolve(r *maxminddb.Reader, ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "LOCAL|内网|Private Network||0|0|1"
	}
	if r == nil {
		return "??||||0|0|0"
	}
	var f wafGeoFlat
	if err := r.Lookup(ip, &f); err != nil {
		return "??||||0|0|0"
	}
	zh := f.Country.Zh
	if zh == "" {
		zh = f.Country.En
	}
	prov := f.Province.Zh
	if prov == "" {
		prov = f.Province.En
	}
	return fmt.Sprintf("%s|%s|%s|%s|%g|%g|0", f.Iso, zh, f.Country.En, prov, f.Latitude, f.Longitude)
}

// wafAtoiDefault 小工具
func wafAtoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func wafAtof(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}
