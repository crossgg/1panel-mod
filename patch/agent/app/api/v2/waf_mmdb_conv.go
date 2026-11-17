package v2

// 1Panel v2.x 社区版 WAF —— mmdb 结构识别与「GeoLite2 → 1pwaf 扁平结构」转换
//
// 背景（实测结论）：
//   1pwaf 与 1Panel agent 的 utils/geo/geo.go 都按下列「扁平」结构读取 GeoIP.mmdb：
//     { iso:"CN", country:{en:"China", zh:"中国"},
//       province:{en:"Jiangsu", zh:"江苏"}, latitude:32.06, longitude:118.76 }
//   province 是顶层字段，且是 {en,zh} 双语表。
//
//   而 MaxMind GeoLite2-City.mmdb 是嵌套结构：
//     { country:{iso_code,names:{en,zh-CN}}, location:{latitude,longitude},
//       subdivisions:[{names:{en,zh-CN}}], city:{names:{...}} }
//   直接把 GeoLite2-City 丢进 data/geo/GeoIP.mmdb 会导致：
//     - province 变成 nil  → 地区访问限制（省份）全部失效
//     - latitude/longitude 变成 nil → 拦截地图、监控地图丢点
//     - country.zh 变成 nil → 中文国家名显示为空
//   所以这里提供「自动识别 + 自动转换」：识别为 MaxMind 嵌套结构时，
//   用 mmdbwriter 重建一棵保持原 CIDR 覆盖的扁平结构库。

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang"
)

// wafGeoLocation 1pwaf 扁平结构里的双语名字对象
type wafGeoLocation struct {
	En string `maxminddb:"en"`
	Zh string `maxminddb:"zh"`
	// 下面两个仅用于识别 MaxMind 原始结构
	ZhCN string `maxminddb:"zh-CN"`
	ZhTW string `maxminddb:"zh-TW"`
}

// wafGeoFlat 1pwaf 期望的扁平结构
type wafGeoFlat struct {
	Iso       string          `maxminddb:"iso"`
	Country   wafGeoLocation  `maxminddb:"country"`
	Province  wafGeoLocation  `maxminddb:"province"`
	City      wafGeoLocation  `maxminddb:"city"`
	Latitude  float64         `maxminddb:"latitude"`
	Longitude float64         `maxminddb:"longitude"`
	ASN       uint            `maxminddb:"asn"`
}

// wafGeoNested MaxMind GeoLite2-City / Country 的原始嵌套结构
type wafGeoNested struct {
	Country struct {
		ISO   string         `maxminddb:"iso_code"`
		Names wafGeoLocation `maxminddb:"names"`
	} `maxminddb:"country"`
	Registered struct {
		ISO   string         `maxminddb:"iso_code"`
		Names wafGeoLocation `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	City struct {
		Names wafGeoLocation `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Lat float64 `maxminddb:"latitude"`
		Lon float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Subdivisions []struct {
		Names wafGeoLocation `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// wafGeoProbeIPs 用于结构探测的样本 IP（覆盖中美欧澳 + 国内多省）
var wafGeoProbeIPs = []string{
	"8.8.8.8", "1.1.1.1", "81.2.69.142", "1.2.3.4",
	"114.114.114.114", "220.181.38.148", "183.6.50.1", "223.5.5.5",
}

// wafMMDBSchema 识别结果
type wafMMDBSchema struct {
	Kind       string // flat（1pwaf 可用）/ maxmind（GeoLite2 嵌套，需转换）/ unknown
	Type       string // metadata.database_type
	IPVersion  uint
	BuildEpoch string
	HasProv    bool
	HasCoord   bool
	Ok         bool
	Reason     string
}

func (s wafMMDBSchema) Label() string {
	switch s.Kind {
	case "flat":
		if s.HasProv {
			return "1pwaf 扁平结构（含省份）"
		}
		return "1pwaf 扁平结构（无省份）"
	case "maxmind":
		if s.HasProv {
			return "MaxMind GeoLite2 嵌套结构（含省份）"
		}
		return "MaxMind GeoLite2 嵌套结构"
	}
	return "无法识别"
}

// wafMMDBSchemaDetect 读 metadata + 抽样解码，判断这个 mmdb 能不能被 1pwaf 直接使用
func wafMMDBSchemaDetect(buf []byte) wafMMDBSchema {
	var out wafMMDBSchema
	if len(buf) < 1024 {
		out.Reason = "文件太小"
		return out
	}
	r, err := maxminddb.FromBytes(buf)
	if err != nil {
		out.Reason = "mmdb 解析失败：" + err.Error()
		return out
	}
	out.Ok = true
	out.Type = r.Metadata.DatabaseType
	out.IPVersion = r.Metadata.IPVersion
	if r.Metadata.BuildEpoch > 0 {
		out.BuildEpoch = time.Unix(int64(r.Metadata.BuildEpoch), 0).Format("2006-01-02")
	}

	flatHit, nestedHit := 0, 0
	for _, s := range wafGeoProbeIPs {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		var f wafGeoFlat
		if err := r.Lookup(ip, &f); err == nil {
			if f.Iso != "" || f.Country.En != "" {
				flatHit++
			}
			if f.Province.En != "" || f.Province.Zh != "" {
				out.HasProv = true
			}
			if f.Latitude != 0 || f.Longitude != 0 {
				out.HasCoord = true
			}
		}
		var n wafGeoNested
		if err := r.Lookup(ip, &n); err == nil {
			if n.Country.ISO != "" || n.Country.Names.En != "" {
				nestedHit++
			}
			if len(n.Subdivisions) > 0 {
				out.HasProv = true
			}
			if n.Location.Lat != 0 || n.Location.Lon != 0 {
				out.HasCoord = true
			}
		}
	}

	switch {
	case flatHit > 0:
		out.Kind = "flat"
	case nestedHit > 0:
		out.Kind = "maxmind"
	default:
		out.Kind = "unknown"
		out.Reason = "样本 IP 查不到任何国家字段，可能不是地理库"
	}
	return out
}

// wafMMDBConvertFlat 把 MaxMind 嵌套结构重建成 1pwaf 扁平结构
// 返回新的 mmdb 字节；prog 用于上报进度（pct 0-100）
func wafMMDBConvertFlat(src []byte, prog func(pct int, msg string)) ([]byte, error) {
	r, err := maxminddb.FromBytes(src)
	if err != nil {
		return nil, fmt.Errorf("解析源库失败：%w", err)
	}
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "1pwaf-GeoIP",
		RecordSize:   28,
		IPVersion:    6,
		Languages:    []string{"en", "zh"},
		Description: map[string]string{
			"en": "Converted from MaxMind GeoLite2 to the flat schema used by 1pwaf (country/province/iso/latitude/longitude). Source data (c) MaxMind, CC BY-SA 4.0.",
			"zh": "由 MaxMind GeoLite2 转换为 1pwaf 扁平结构（country/province/iso/latitude/longitude）。数据来源 MaxMind，许可 CC BY-SA 4.0。",
		},
		BuildEpoch:              time.Now().Unix(),
		IncludeReservedNetworks: true,
	})
	if err != nil {
		return nil, fmt.Errorf("创建写入器失败：%w", err)
	}

	nw := r.Networks()
	var (
		total, kept, noProv int
		rec                 wafGeoNested
	)
	for nw.Next() {
		total++
		if prog != nil && total%200000 == 0 {
			prog(0, fmt.Sprintf("已扫描 %d 万个网段，写入 %d 万条", total/10000, kept/10000))
		}
		rec = wafGeoNested{}
		subnet, err := nw.Network(&rec)
		if err != nil || subnet == nil {
			continue
		}
		iso := firstNonEmpty(rec.Country.ISO, rec.Registered.ISO)
		cEn := firstNonEmpty(rec.Country.Names.En, rec.Registered.Names.En)
		cZh := firstNonEmpty(rec.Country.Names.ZhCN, rec.Registered.Names.ZhCN, rec.Country.Names.Zh, cEn)
		if iso == "" && cEn == "" {
			continue
		}
		m := mmdbtype.Map{}
		if iso != "" {
			m["iso"] = mmdbtype.String(iso)
		}
		if cEn != "" || cZh != "" {
			c := mmdbtype.Map{}
			if cEn != "" {
				c["en"] = mmdbtype.String(cEn)
			}
			if cZh != "" {
				c["zh"] = mmdbtype.String(cZh)
			}
			m["country"] = c
		}
		if len(rec.Subdivisions) > 0 {
			s0 := rec.Subdivisions[0]
			pEn := s0.Names.En
			pZh := firstNonEmpty(s0.Names.ZhCN, s0.Names.Zh, pEn)
			if pEn != "" || pZh != "" {
				p := mmdbtype.Map{}
				if pEn != "" {
					p["en"] = mmdbtype.String(pEn)
				}
				if pZh != "" {
					p["zh"] = mmdbtype.String(pZh)
				}
				m["province"] = p
			}
		}
		if _, ok := m["province"]; !ok {
			noProv++
		}
		if rec.City.Names.En != "" || rec.City.Names.ZhCN != "" {
			c := mmdbtype.Map{}
			if rec.City.Names.En != "" {
				c["en"] = mmdbtype.String(rec.City.Names.En)
			}
			if z := firstNonEmpty(rec.City.Names.ZhCN, rec.City.Names.Zh, rec.City.Names.En); z != "" {
				c["zh"] = mmdbtype.String(z)
			}
			m["city"] = c
		}
		if rec.Location.Lat != 0 || rec.Location.Lon != 0 {
			m["latitude"] = mmdbtype.Float64(rec.Location.Lat)
			m["longitude"] = mmdbtype.Float64(rec.Location.Lon)
		}
		if err := tree.Insert(subnet, m); err != nil {
			continue
		}
		kept++
	}

	var out bytes.Buffer
	if _, err := tree.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("生成新库失败：%w", err)
	}
	if prog != nil {
		prog(100, fmt.Sprintf("转换完成：源 %d 个网段，写入 %d 条，其中 %d 条无省份信息", total, kept, noProv))
	}
	return out.Bytes(), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
