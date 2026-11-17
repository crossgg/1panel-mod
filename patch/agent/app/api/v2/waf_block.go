package v2

// 1Panel v2.x 社区版 WAF「封锁记录」API（补丁文件，新增）
//
// 对应官方 xpack：
//   GET  /xpack/waf/block/export    导出封锁记录
//   POST /xpack/waf/block/remove    解封
//
// 1pwaf 的封锁数据在 data/db/waf/block_ips.db：
//   block_ips(id, event_id, ip_id, is_block, blocking_time, attack_log_id, create_date)
//   ip_id 指向同目录 ips.db 的 ips(id, value)
//
// blocking_time 语义随版本不同（有的是到期时间戳，有的是封禁时长），
// 这里按数值大小自适应：>1e12 视为毫秒时间戳，>1e9 视为秒时间戳，否则视为时长（秒）。

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/gin-gonic/gin"
	_ "github.com/glebarez/go-sqlite"
)

func wafWafDbDir() (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("没找到 1pwaf 的 conf 目录")
	}
	dir := filepath.Join(wafDataDir(conf), "db", "waf")
	if !wafDirExists(dir) {
		return "", fmt.Errorf("没找到 WAF 数据库目录：%s", dir)
	}
	return dir, nil
}

// 打开可写连接（解封要 DELETE）
func wafOpenRW(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

type wafBlockItem struct {
	ID           int64  `json:"id"`
	IP           string `json:"ip"`
	IsBlock      int    `json:"is_block"`
	Status       string `json:"status"` // 封禁中 / 已解封
	BlockingTime int64  `json:"blocking_time"`
	CreateDate   string `json:"create_date"`
	ExpireAt     string `json:"expire_at"`
	Remain       int64  `json:"remain"` // 剩余秒数，<=0 表示已到期
	EventID      string `json:"event_id"`
}

// 把 blocking_time 归一成「到期时间」
//
// create_date 由 sqlite 驱动读出来可能是 "2006-01-02 15:04:05" 或 RFC3339
// （"2006-01-02T15:04:05Z"），这里统一解析成 time.Time 再算。
func wafParseWafTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02T15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// wafBlockExpire 返回 (到期时间, 剩余秒数, 归一后的创建时间)
func wafBlockExpire(v int64, createDate string) (expireAt string, remain int64, created string) {
	now := time.Now()
	createdAt, ok := wafParseWafTime(createDate)
	if ok {
		created = createdAt.UTC().Format("2006-01-02 15:04:05")
	} else {
		created = createDate
	}
	switch {
	case v > 1_000_000_000_000: // 毫秒时间戳
		t := time.UnixMilli(v)
		return t.Local().Format("2006-01-02 15:04:05"), int64(t.Sub(now).Seconds()), created
	case v > 1_000_000_000: // 秒时间戳
		t := time.Unix(v, 0)
		return t.Local().Format("2006-01-02 15:04:05"), int64(t.Sub(now).Seconds()), created
	case v > 0 && ok: // 时长（秒），基于 create_date 推算（sqlite 的 DATETIME('now') 是 UTC）
		end := createdAt.Add(time.Duration(v) * time.Second)
		return end.Local().Format("2006-01-02 15:04:05"), int64(end.Sub(now).Seconds()), created
	}
	return "", 0, created
}

// 读取 ips.db → id 到 IP 的映射
func wafBlockIPMap(dir string) map[int64]string {
	out := make(map[int64]string, 256)
	db, err := wafOpenRO(filepath.Join(dir, "ips.db"))
	if err != nil {
		return out
	}
	defer db.Close()
	rows, err := db.Query("SELECT id, value FROM ips")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var v string
		if rows.Scan(&id, &v) == nil {
			out[id] = v
		}
	}
	return out
}

func wafBlockReadAll(dir string) ([]wafBlockItem, error) {
	ipMap := wafBlockIPMap(dir)
	db, err := wafOpenRO(filepath.Join(dir, "block_ips.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, event_id, ip_id, is_block, blocking_time, create_date
		FROM block_ips ORDER BY id DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]wafBlockItem, 0, 64)
	for rows.Next() {
		var it wafBlockItem
		var eventID sql.NullString
		var ipID sql.NullInt64
		var isBlock, blockingTime sql.NullInt64
		var createDate sql.NullString
		if err := rows.Scan(&it.ID, &eventID, &ipID, &isBlock, &blockingTime, &createDate); err != nil {
			continue
		}
		it.EventID = eventID.String
		it.IP = ipMap[ipID.Int64]
		it.IsBlock = int(isBlock.Int64)
		it.BlockingTime = blockingTime.Int64
		it.ExpireAt, it.Remain, it.CreateDate = wafBlockExpire(it.BlockingTime, createDate.String)
		switch {
		case it.IsBlock != 1:
			it.Status = "free"
		case it.BlockingTime <= 0: // 没有时间信息，视为永久封禁
			it.Status = "blocking"
		case it.Remain > 0:
			it.Status = "blocking"
		default:
			it.Status = "free"
		}
		out = append(out, it)
	}
	return out, nil
}

// WafBlockList GET /api/v2/waf-log/block/list?page&size&kw&status
func (b *BaseApi) WafBlockList(c *gin.Context) {
	dir, err := wafWafDbDir()
	if err != nil {
		helper.SuccessWithData(c, gin.H{"ok": false, "hint": err.Error(), "items": []gin.H{}, "total": 0})
		return
	}
	items, err := wafBlockReadAll(dir)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}

	kw := strings.ToLower(strings.TrimSpace(c.Query("kw")))
	status := c.Query("status")
	filtered := make([]wafBlockItem, 0, len(items))
	for _, it := range items {
		if kw != "" && !strings.Contains(strings.ToLower(it.IP), kw) {
			continue
		}
		if status == "blocking" && it.Status != "blocking" {
			continue
		}
		if status == "free" && it.Status != "free" {
			continue
		}
		filtered = append(filtered, it)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].ID > filtered[j].ID })

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 20
	}
	off := (page - 1) * size
	if off > len(filtered) {
		off = len(filtered)
	}
	end := off + size
	if end > len(filtered) {
		end = len(filtered)
	}

	// 顺带统计一下封禁中的数量，列表页头部要用
	blocking := 0
	for _, it := range items {
		if it.Status == "blocking" {
			blocking++
		}
	}

	helper.SuccessWithData(c, gin.H{
		"ok": true, "items": filtered[off:end], "total": len(filtered),
		"page": page, "size": size, "blocking": blocking, "all": len(items),
	})
}

type wafBlockRemoveReq struct {
	IDs []int64 `json:"ids"`
}

// WafBlockRemove POST /api/v2/waf-log/block/remove {ids:[...]}
func (b *BaseApi) WafBlockRemove(c *gin.Context) {
	var req wafBlockRemoveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		wafBad(c, "请选择要解封的记录")
		return
	}
	dir, err := wafWafDbDir()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	db, err := wafOpenRW(filepath.Join(dir, "block_ips.db"))
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	defer db.Close()

	removed := int64(0)
	for _, id := range req.IDs {
		res, err := db.Exec("DELETE FROM block_ips WHERE id = ?", id)
		if err != nil {
			continue
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	helper.SuccessWithData(c, gin.H{
		"saved": true, "removed": removed,
		"hint": "已从封锁记录中移除。1pwaf 的临时封禁状态缓存在 OpenResty 共享内存里，" +
			"重启 OpenResty 后才会彻底解除；如需立即生效，可把该 IP 加入白名单。",
	})
}

type wafBlockAddReq struct {
	IPs  []string `json:"ips"`
	Kind string   `json:"kind"` // black / white
}

// WafBlockAdd POST /api/v2/waf-log/block/add {ips:[], kind:"black"|"white"}
// 把 IP 永久拉黑 / 加白（写 ipBlack.json / ipWhite.json）
func (b *BaseApi) WafBlockAdd(c *gin.Context) {
	var req wafBlockAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, "参数错误："+err.Error())
		return
	}
	if len(req.IPs) == 0 {
		wafBad(c, "IP 不能为空")
		return
	}
	kind := "ipBlack"
	if req.Kind == "white" {
		kind = "ipWhite"
	}
	entries, err := wafBwRead(kind)
	if err != nil {
		wafBwFail(c, err)
		return
	}
	exist := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Start != "" {
			exist[e.Start] = true
		}
	}
	added, skipped, failed := 0, 0, make([]string, 0)
	for _, raw := range req.IPs {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		start, end, err := wafIPv4Range(ip)
		if err != nil {
			failed = append(failed, ip+": "+err.Error())
			continue
		}
		if exist[start] {
			skipped++
			continue
		}
		exist[start] = true
		entries = append(entries, wafBwEntry{
			State: "on", Name: "来自封锁记录", Rule: wafIPv4Display(start, end),
			Start: start, End: end, Type: "ipArr",
		})
		added++
	}
	if added > 0 {
		p, err := wafBwPath(kind)
		if err != nil {
			wafBwFail(c, err)
			return
		}
		if _, err := wafBackupFile(p); err != nil {
			_ = err
		}
		buf, err := json.MarshalIndent(map[string]interface{}{"rules": wafBwMarshal(kind, entries)}, "", "  ")
		if err != nil {
			wafBwFail(c, err)
			return
		}
		buf = append(buf, '\n')
		if err := os.WriteFile(p, buf, 0o644); err != nil {
			wafBwFail(c, err)
			return
		}
	}
	res := gin.H{"saved": added > 0, "added": added, "skipped": skipped, "failed": failed}
	if added > 0 {
		if out, warns, err := wafReloadConf(); err != nil {
			res["reloaded"] = false
			res["reload_error"] = err.Error()
			res["reload_output"] = out
			res["warnings"] = warns
		} else {
			res["reloaded"] = true
			res["reload_output"] = out
		}
	}
	helper.SuccessWithData(c, res)
}

// WafBlockExport GET /api/v2/waf-log/block/export
func (b *BaseApi) WafBlockExport(c *gin.Context) {
	dir, err := wafWafDbDir()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	items, err := wafBlockReadAll(dir)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"ID", "IP", "状态", "封禁时间", "到期时间", "剩余秒", "event_id"})
	for _, it := range items {
		st := "已解封"
		if it.Status == "blocking" {
			st = "封禁中"
		}
		_ = w.Write([]string{
			strconv.FormatInt(it.ID, 10), it.IP, st, it.CreateDate, it.ExpireAt,
			strconv.FormatInt(it.Remain, 10), it.EventID,
		})
	}
	w.Flush()
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="waf-block.csv"`)
	c.String(200, "\ufeff"+sb.String())
}
