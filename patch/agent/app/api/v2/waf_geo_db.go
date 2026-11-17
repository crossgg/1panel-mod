package v2

// 1Panel v2.x 社区版 WAF「IP 库（mmdb）维护」（补丁文件，新增）
//
// 三个库：BlackIP.mmdb（恶意 IP 段）/ SpiderIP.mmdb（爬虫 IP 段）/ GeoIP.mmdb（国家+省份）
// 官方 xpack 通过 POST /xpack/waf/location/update {"type":"blackIP|spiderIP|geoIP"} 更新，
// 但下载地址在 xpack 的 Go 侧，镜像里没有任何 URL 常量（已 strings 全量确认），
// 因此这里提供两种可用的替代来源：
//   1) extract —— 直接从 openresty 镜像里取出内置库（镜像内 BlackIP 比现网大 24 倍）
//   2) url     —— 自定义地址，支持 .mmdb / .mmdb.gz / .tar.gz / .zip
//                 （MaxMind 官方的 GeoLite2 就是 tar.gz，P3TERX 的 release 是裸 .mmdb）
//
// ★ 结构自动适配：GeoLite2-City.mmdb 是 MaxMind 嵌套结构，1pwaf 要的是扁平结构
//   （顶层 iso / country{en,zh} / province{en,zh} / latitude / longitude）。
//   下载后自动识别，识别到嵌套结构就用 mmdbwriter 重建一份扁平库再落盘。
//   转换大约需要 6~10 分钟（1600 万网段），所以 URL 更新走后台任务 + 轮询进度。
//
// 所有写操作都会先备份 <name>.mmdb.bak.<unix>，失败可一键 restore。

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

var wafGeoDBFiles = []struct {
	Name string
	Desc string
	Tip  string
}{
	{"BlackIP", "恶意 IP 段（命中即拦截）", "纯 IP 段库，来自 openresty 镜像或自定义地址"},
	{"SpiderIP", "搜索引擎 / 爬虫 IP 段（配合「允许蜘蛛访问」使用）", "纯 IP 段库，来自 openresty 镜像或自定义地址"},
	{"GeoIP", "IP 归属地（国家 + 省份，地区访问限制依赖它）", "必须是扁平结构；GeoLite2-City 会被自动转换"},
}

const wafGeoDBMaxSize = 300 << 20 // 300MB 上限（压缩包按解压后计）

func wafGeoDir() (string, error) {
	conf := wafConfDir()
	if conf == "" {
		return "", fmt.Errorf("未找到 1pwaf 配置目录")
	}
	d := filepath.Join(wafDataDir(conf), "geo")
	if !wafDirExists(d) {
		return "", fmt.Errorf("IP 库目录不存在：%s", d)
	}
	return d, nil
}

func wafGeoDBName(name string) (string, error) {
	for _, it := range wafGeoDBFiles {
		if it.Name == name {
			return name + ".mmdb", nil
		}
	}
	return "", fmt.Errorf("name 只能是 BlackIP / SpiderIP / GeoIP")
}

// wafMMDBCheck 粗略校验：MaxMind 格式标记 + 是否含省份字段（保留给旧调用点）
func wafMMDBCheck(buf []byte) (bool, string, bool) {
	if len(buf) < 1024 {
		return false, "文件太小，不是有效的 mmdb", false
	}
	if buf[0] == '<' {
		return false, "看起来是 HTML/文本，不是二进制 mmdb", false
	}
	if !bytes.Contains(buf, []byte("MaxMind.com")) {
		return false, "缺少 MaxMind 元数据标记，不是标准 mmdb", false
	}
	s := wafMMDBSchemaDetect(buf)
	if !s.Ok {
		return false, s.Reason, false
	}
	return true, "", s.HasProv
}

func wafGeoDBBackup(p string) string {
	ts := time.Now().Unix()
	bak := fmt.Sprintf("%s.bak.%d", p, ts)
	if err := copyFile(p, bak); err != nil {
		return ""
	}
	return bak
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	return os.Rename(tmp, dst)
}

// wafGeoDBItem 组装单个库的信息
func wafGeoDBItem(dir, name, desc, tip string) gin.H {
	p := filepath.Join(dir, name+".mmdb")
	row := gin.H{"name": name, "desc": desc, "tip": tip, "path": p}
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		row["exists"] = false
		baks, _ := filepath.Glob(p + ".bak.*")
		row["backups"] = len(baks)
		return row
	}
	row["exists"] = true
	row["size"] = st.Size()
	row["mtime"] = st.ModTime().Format("2006-01-02 15:04:05")
	if buf, err := os.ReadFile(p); err == nil {
		s1 := sha1.Sum(buf)
		s2 := sha256.Sum256(buf)
		row["sha1"] = hex.EncodeToString(s1[:])
		row["sha256"] = hex.EncodeToString(s2[:])
		sch := wafMMDBSchemaDetect(buf)
		row["valid"] = sch.Ok
		row["reason"] = sch.Reason
		row["has_province"] = sch.HasProv
		row["has_coord"] = sch.HasCoord
		row["schema"] = sch.Kind
		row["schema_label"] = sch.Label()
		row["db_type"] = sch.Type
		row["build_epoch"] = sch.BuildEpoch
		if name != "GeoIP" {
			// BlackIP / SpiderIP 是纯 IP 段库，本来就没有国家/省份字段。
			// 判定器用地理库的标准去试解必然落 unknown，这里清掉 reason，避免前端误标成错误。
			row["has_province"] = false
			row["has_coord"] = false
			row["reason"] = ""
			row["note"] = "纯 IP 段库，无需国家/省份字段"
			if sch.Ok {
				row["schema"] = "iplist"
				row["schema_label"] = "IP 段库（非地理库）"
			}
		}
	}
	baks, _ := filepath.Glob(p + ".bak.*")
	row["backups"] = len(baks)
	return row
}

// WafGeoDBInfo GET /api/v2/waf-log/geo/db
func (b *BaseApi) WafGeoDBInfo(c *gin.Context) {
	dir, err := wafGeoDir()
	if err != nil {
		wafFailErr(c, err)
		return
	}
	image := ""
	if cs := wafFindContainers(); len(cs) > 0 {
		image = cs[0].Image
	}
	items := make([]gin.H, 0, len(wafGeoDBFiles))
	for _, it := range wafGeoDBFiles {
		items = append(items, wafGeoDBItem(dir, it.Name, it.Desc, it.Tip))
	}
	wafOKData(c, gin.H{"ok": true, "dir": dir, "image": image, "items": items,
		"attribution": "GeoLite2 数据由 MaxMind 提供（CC BY-SA 4.0）；P3TERX/GeoLite.mmdb 为其每日构建镜像",
		"hint": "GeoIP 必须是 1pwaf 扁平结构（顶层 province）；下载到 MaxMind 嵌套结构会自动转换"})
}

// ---------------------------------------------------------------------------
// 后台任务（下载 + 解包 + 转换 + 落盘 + 重载）
// ---------------------------------------------------------------------------

type wafGeoJob struct {
	Name   string    `json:"name"`
	State  string    `json:"state"` // running / done / error
	Phase  string    `json:"phase"`
	Pct    int       `json:"pct"`
	Msg    string    `json:"msg"`
	Err    string    `json:"err"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Result gin.H     `json:"result"`
}

var wafGeoJobStore = struct {
	sync.Mutex
	m map[string]*wafGeoJob
}{m: map[string]*wafGeoJob{}}

func (j *wafGeoJob) set(phase string, pct int, msg string) {
	wafGeoJobStore.Lock()
	defer wafGeoJobStore.Unlock()
	j.Phase = phase
	j.Pct = pct
	if msg != "" {
		j.Msg = msg
	}
}

func wafGeoJobGet(name string) *wafGeoJob {
	wafGeoJobStore.Lock()
	defer wafGeoJobStore.Unlock()
	return wafGeoJobStore.m[name]
}

// wafGeoJobBegin 抢占式启动；已有任务在跑时返回 nil
func wafGeoJobBegin(name string) *wafGeoJob {
	wafGeoJobStore.Lock()
	defer wafGeoJobStore.Unlock()
	if old, ok := wafGeoJobStore.m[name]; ok && old.State == "running" {
		return nil
	}
	j := &wafGeoJob{Name: name, State: "running", Phase: "准备", Pct: 1, Start: time.Now()}
	wafGeoJobStore.m[name] = j
	return j
}

func (j *wafGeoJob) finish(err error, res gin.H) {
	wafGeoJobStore.Lock()
	defer wafGeoJobStore.Unlock()
	j.End = time.Now()
	if err != nil {
		j.State = "error"
		j.Err = err.Error()
		j.Pct = 100
		return
	}
	j.State = "done"
	j.Pct = 100
	j.Result = res
}

// WafGeoDBJob GET /api/v2/waf-log/geo/db/job?name=GeoIP
func (b *BaseApi) WafGeoDBJob(c *gin.Context) {
	name := c.Query("name")
	j := wafGeoJobGet(name)
	if j == nil {
		wafOKData(c, gin.H{"ok": true, "state": "idle", "name": name})
		return
	}
	wafGeoJobStore.Lock()
	copy := *j
	wafGeoJobStore.Unlock()
	// running 时 End 还是零值，End.Sub(Start) 会溢出成巨大负数
	elapsed := time.Since(copy.Start).Seconds()
	if !copy.End.IsZero() && copy.End.After(copy.Start) {
		elapsed = copy.End.Sub(copy.Start).Seconds()
	}
	wafOKData(c, gin.H{"ok": true, "job": &copy, "state": copy.State, "phase": copy.Phase,
		"pct": copy.Pct, "msg": copy.Msg, "err": copy.Err, "result": copy.Result,
		"elapsed": int(elapsed)})
}

// ---------------------------------------------------------------------------
// 下载与解包
// ---------------------------------------------------------------------------

// wafGeoHTTPClient 专用下载客户端：
// 国内到 GitHub release 的 TLS 握手经常要 10~25 秒，Go 默认 10s 会直接超时，
// 所以这里放宽握手/响应头超时，并对失败做整体重试。
func wafGeoHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// 直连被墙时不要卡太久，10 秒就换镜像
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 30 * time.Second
	tr.ResponseHeaderTimeout = 120 * time.Second
	tr.ExpectContinueTimeout = 10 * time.Second
	tr.IdleConnTimeout = 120 * time.Second
	tr.MaxIdleConnsPerHost = 4
	return &http.Client{Timeout: 30 * time.Minute, Transport: tr}
}

// wafGeoMirrors：实测连通性排序（2026-11-16 同机 Range 探测）
//   v4.gh-proxy.org 1.45s / 206，gh-proxy.com 3.28s，ghfast.top 302，ghproxy.net 11s
// 只在直连失败或用户显式勾选加速时使用，不替换用户输入。
var wafGeoMirrors = []string{
	"https://v4.gh-proxy.org/",
	"https://gh-proxy.com/",
	"https://ghfast.top/",
	"https://ghproxy.net/",
}

// wafIsGitHub 只认「以 GitHub 域名开头」的地址，避免把已经带镜像前缀的 URL 再套一层
func wafIsGitHub(u string) bool {
	for _, h := range []string{
		"https://github.com/", "http://github.com/",
		"https://raw.githubusercontent.com/", "https://objects.githubusercontent.com/",
		"https://gist.githubusercontent.com/",
	} {
		if strings.HasPrefix(u, h) {
			return true
		}
	}
	return false
}

// wafGeoApplyMirror 支持前缀式（https://xxx/）与模板式（https://xxx/fetch?u={url}）
func wafGeoApplyMirror(mirror, u string) (string, error) {
	m := strings.TrimSpace(mirror)
	if m == "" {
		return u, nil
	}
	if !strings.HasPrefix(m, "http://") && !strings.HasPrefix(m, "https://") {
		return "", fmt.Errorf("自定义加速镜像必须以 http:// 或 https:// 开头")
	}
	if strings.Contains(m, "{url}") {
		return strings.ReplaceAll(m, "{url}", u), nil
	}
	return strings.TrimSuffix(m, "/") + "/" + u, nil
}

// wafGeoCandidates：mirror 非空时优先镜像，原地址随后，内置镜像兜底；默认（mirror 空）
// 仍是直连优先 + 失败自动回退，保持原来的行为。
func wafGeoCandidates(u, mirror string) []string {
	out := make([]string, 0, 6)
	seen := map[string]bool{}
	add := func(x string) {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	if strings.TrimSpace(mirror) != "" {
		if m, err := wafGeoApplyMirror(mirror, u); err == nil {
			add(m)
		}
	}
	add(u)
	if wafIsGitHub(u) {
		for _, m := range wafGeoMirrors {
			if x, err := wafGeoApplyMirror(m, u); err == nil {
				add(x)
			}
		}
	}
	return out
}

// wafGeoDL 是一次成功下载的结果
type wafGeoDL struct {
	Body        []byte
	URL         string
	ContentType string
	Size        int64
}

// wafGeoReadWithStall 读 body，并在「stall 时间内一个字节都没到」时取消请求。
// 这是根治「直连拿到响应头后 body 卡死、永远不回退镜像」的关键：
// 以前 wafGeoGet 只在 cli.Do 失败时才换候选，body 挂起会一直等到 Client.Timeout(30min)。
func wafGeoReadWithStall(ctx context.Context, cancel context.CancelFunc, body io.Reader, stall time.Duration, max int64) ([]byte, error) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > stall {
					cancel()
					return
				}
			}
		}
	}()
	buf := new(bytes.Buffer)
	tmp := make([]byte, 32*1024)
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			last.Store(time.Now().UnixNano())
			buf.Write(tmp[:n])
			if int64(buf.Len()) > max {
				return nil, fmt.Errorf("下载内容超过 300MB，已拒绝")
			}
		}
		if err == io.EOF {
			return buf.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// wafGeoDownload 逐个候选做「完整下载」，任何一个候选停滞/失败都立刻换下一个。
func wafGeoDownload(u, mirror string, prog func(pct int, msg string)) (*wafGeoDL, error) {
	cli := wafGeoHTTPClient()
	cands := wafGeoCandidates(u, mirror)
	var lastErr error
	for i, cand := range cands {
		if i > 0 && prog != nil {
			prog(4, fmt.Sprintf("上一个地址失败（%v），改用 %s", lastErr, wafMirrorHost(cand)))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		req, err := http.NewRequestWithContext(ctx, "GET", cand, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("User-Agent", "1panel-waf-patch/1.0")
		resp, err := cli.Do(req)
		if err != nil {
			lastErr = err
			cancel()
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			cancel()
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				break // 地址本身有问题，镜像也救不了
			}
			continue
		}
		if prog != nil {
			prog(5, fmt.Sprintf("已连接 %s，开始下载 %s", wafMirrorHost(cand), humanSize(resp.ContentLength)))
		}
		raw, err := wafGeoReadWithStall(ctx, cancel, resp.Body, 25*time.Second, int64(wafGeoDBMaxSize)+1)
		used := cand
		ctype := resp.Header.Get("Content-Type")
		size := resp.ContentLength
		if resp.Request != nil && resp.Request.URL != nil {
			used = resp.Request.URL.String()
		}
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("下载中断：%v", err)
			cancel()
			continue
		}
		cancel()
		if len(raw) == 0 {
			lastErr = fmt.Errorf("下载内容为空（地址可能已失效或需要鉴权）")
			continue
		}
		if prog != nil {
			prog(20, fmt.Sprintf("下载完成 %s", humanSize(int64(len(raw)))))
		}
		return &wafGeoDL{Body: raw, URL: used, ContentType: ctype, Size: size}, nil
	}
	return nil, fmt.Errorf("所有下载地址均失败：%v", lastErr)
}

func wafMirrorHost(u string) string {
	if i := strings.Index(u, "//"); i >= 0 {
		rest := u[i+2:]
		if j := strings.Index(rest, "/"); j > 0 {
			return rest[:j]
		}
	}
	return u
}

// wafGeoFetch 下载并（在需要时）解包，返回 mmdb 字节 + 来源描述
func wafGeoFetch(u string, wantName, mirror string, prog func(pct int, msg string)) ([]byte, string, error) {
	dl, err := wafGeoDownload(u, mirror, prog)
	if err != nil {
		return nil, "", err
	}
	raw := dl.Body
	low := strings.ToLower(u)
	ct := strings.ToLower(dl.ContentType)
	name := ""

	// 1) tar.gz / tgz
	if strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz") ||
		(bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) && looksLikeTarGz(raw) && !strings.HasSuffix(low, ".gz")) {
		buf, ent, err := wafUntarGz(raw, wantName)
		if err != nil {
			return nil, "", err
		}
		name = ent
		raw = buf
	} else if strings.HasSuffix(low, ".gz") || bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		// 2) 单文件 .gz
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "", fmt.Errorf("gzip 解压失败：%v", err)
		}
		buf, err := io.ReadAll(io.LimitReader(zr, int64(wafGeoDBMaxSize)+1))
		zr.Close()
		if err != nil {
			return nil, "", fmt.Errorf("gzip 解压失败：%v", err)
		}
		if len(buf) > wafGeoDBMaxSize {
			return nil, "", fmt.Errorf("解压后超过 300MB，已拒绝")
		}
		name = strings.TrimSuffix(filepath.Base(low), ".gz")
		raw = buf
	} else if strings.HasSuffix(low, ".zip") || (bytes.HasPrefix(raw, []byte("PK\x03\x04")) && ct != "") {
		// 3) zip
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, "", fmt.Errorf("zip 解压失败：%v", err)
		}
		var best *zip.File
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".mmdb") {
				continue
			}
			if best == nil || f.UncompressedSize64 > best.UncompressedSize64 {
				best = f
			}
		}
		if best == nil {
			return nil, "", fmt.Errorf("zip 包内没有 .mmdb 文件")
		}
		rc, err := best.Open()
		if err != nil {
			return nil, "", fmt.Errorf("读取 zip 条目失败：%v", err)
		}
		buf, err := io.ReadAll(io.LimitReader(rc, int64(wafGeoDBMaxSize)+1))
		rc.Close()
		if err != nil {
			return nil, "", fmt.Errorf("读取 zip 条目失败：%v", err)
		}
		name = best.Name
		raw = buf
	} else {
		name = filepath.Base(low)
	}

	if len(raw) < 1024 {
		return nil, "", fmt.Errorf("解出的文件只有 %d 字节，不是有效的 mmdb", len(raw))
	}
	if prog != nil {
		prog(28, fmt.Sprintf("解包完成：%s（%s）", name, humanSize(int64(len(raw)))))
	}
	used := dl.URL
	src := "url:" + u
	if used != u {
		src = fmt.Sprintf("url:%s（%s，经加速 %s）", u, name, wafMirrorHost(used))
	} else if name != "" && name != filepath.Base(low) {
		src = fmt.Sprintf("url:%s (%s)", u, name)
	}
	return raw, src, nil
}

// looksLikeTarGz 简单看 gzip 解压头里是否像 tar（避免把单文件 gz 当 tar）
func looksLikeTarGz(raw []byte) bool {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	defer zr.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(zr, head)
	if n < 262 {
		return false
	}
	return string(head[257:262]) == "ustar"
}

// wafUntarGz 从 tar.gz 里挑一个最合适的 .mmdb
func wafUntarGz(raw []byte, wantName string) ([]byte, string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("gzip 解压失败：%v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var (
		bestBuf  []byte
		bestName string
		names    []string
	)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("tar 解析失败：%v", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(h.Name)
		if !strings.HasSuffix(strings.ToLower(base), ".mmdb") {
			continue
		}
		names = append(names, base)
		buf, err := io.ReadAll(io.LimitReader(tr, int64(wafGeoDBMaxSize)+1))
		if err != nil {
			return nil, "", fmt.Errorf("读取 %s 失败：%v", base, err)
		}
		// 优先取体积最大的（官方包里 City > Country），GeoIP 目标优先含 City
		better := bestBuf == nil || len(buf) > len(bestBuf)
		if wantName == "GeoIP" && strings.Contains(strings.ToLower(base), "city") &&
			(bestName == "" || !strings.Contains(strings.ToLower(bestName), "city")) {
			better = true
		}
		if better {
			bestBuf, bestName = buf, base
		}
	}
	if bestBuf == nil {
		if len(names) == 0 {
			return nil, "", fmt.Errorf("压缩包里没有 .mmdb 文件")
		}
		return nil, "", fmt.Errorf("压缩包内 .mmdb 读取失败")
	}
	return bestBuf, bestName, nil
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	case n > 0:
		return fmt.Sprintf("%d B", n)
	}
	return "未知大小"
}

// ---------------------------------------------------------------------------
// 落盘（备份 + 原子替换 + 可选重载）
// ---------------------------------------------------------------------------

func wafGeoDBSave(dir, file string, buf []byte, name string, src string, hasProv bool, reload bool) gin.H {
	target := filepath.Join(dir, file)
	tmp := target + ".new"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return gin.H{"error": "写入临时文件失败：" + err.Error()}
	}
	bak := ""
	if wafPathExists(target) {
		bak = wafGeoDBBackup(target)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return gin.H{"error": "替换失败：" + err.Error()}
	}
	sum := sha256.Sum256(buf)
	res := gin.H{"saved": true, "name": name, "source": src, "size": len(buf),
		"sha256": hex.EncodeToString(sum[:]),
		"has_province": hasProv, "backup": bak, "path": target}
	warns := make([]string, 0, 3)
	if name == "GeoIP" && !hasProv {
		warns = append(warns, "该库没有省份字段，省份限制会失效（国家限制不受影响）")
	}
	if reload {
		outTxt, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = outTxt
		warns = append(warns, w...)
	}
	if len(warns) > 0 {
		res["warnings"] = warns
	}
	return res
}

// wafGeoJobRunURL 后台任务主体
func wafGeoJobRunURL(j *wafGeoJob, dir, file, name, u, mirror string, convert bool, reload bool) {
	defer func() {
		if r := recover(); r != nil {
			j.finish(fmt.Errorf("内部错误：%v", r), nil)
		}
	}()

	j.set("下载", 3, "正在下载 "+u)
	buf, src, err := wafGeoFetch(u, name, mirror, func(pct int, msg string) { j.set("下载", pct, msg) })
	if err != nil {
		j.finish(err, nil)
		return
	}

	j.set("识别", 30, "正在识别库结构")
	sch := wafMMDBSchemaDetect(buf)
	if !sch.Ok {
		j.finish(fmt.Errorf("不是有效的 mmdb：%s", sch.Reason), nil)
		return
	}
	if sch.Kind == "unknown" {
		j.finish(fmt.Errorf("无法识别该库结构：%s", sch.Reason), nil)
		return
	}

	converted := false
	if sch.Kind == "maxmind" {
		if name != "GeoIP" {
			j.finish(fmt.Errorf("BlackIP / SpiderIP 需要的不是地理库，无法使用 %s", sch.Label()), nil)
			return
		}
		if !convert {
			j.finish(fmt.Errorf("该库是 %s，与 1pwaf 扁平结构不兼容（省份限制会失效），已终止。可勾选「自动转换」后重试", sch.Label()), nil)
			return
		}
		j.set("转换", 32, "检测到 MaxMind 嵌套结构，正在转换为 1pwaf 扁平结构（1600 万网段，约 6~10 分钟，请勿关闭页面）")
		calls := 0
		nb, err := wafMMDBConvertFlat(buf, func(_ int, msg string) {
			// 转换占 33~91：每 200k 网段回调一次，GeoLite2-City 约 84 次
			calls++
			pct := 33 + calls*58/84
			if pct > 91 {
				pct = 91
			}
			j.set("转换", pct, msg)
		})
		if err != nil {
			j.finish(err, nil)
			return
		}
		buf = nb
		converted = true
		sch = wafMMDBSchemaDetect(buf)
		if sch.Kind != "flat" {
			j.finish(fmt.Errorf("转换后仍不是可用的扁平结构：%s", sch.Reason), nil)
			return
		}
		j.set("转换", 92, fmt.Sprintf("转换完成，新库 %s（%s）", humanSize(int64(len(buf))), sch.Label()))
	}

	j.set("写入", 94, "正在备份并替换现有文件")
	res := wafGeoDBSave(dir, file, buf, name, src, sch.HasProv, false)
	if e, ok := res["error"]; ok {
		j.finish(fmt.Errorf("%v", e), nil)
		return
	}
	res["converted"] = converted
	res["schema"] = sch.Kind
	res["schema_label"] = sch.Label()
	res["db_type"] = sch.Type
	res["build_epoch"] = sch.BuildEpoch

	if reload {
		j.set("重载", 97, "正在校验并重载 openresty 配置")
		outTxt, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = outTxt
		if len(w) > 0 {
			res["warnings"] = w
		}
	}
	j.finish(nil, res)
}

// ---------------------------------------------------------------------------
// 接口
// ---------------------------------------------------------------------------

type wafGeoDBReq struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Live    bool   `json:"reload"`
	Convert *bool  `json:"convert"`
	Async   *bool  `json:"async"`
	Mirror  string `json:"mirror"`
}

// WafGeoDBExtract POST /api/v2/waf-log/geo/db/extract {name}
// 从当前 openresty 镜像里取出内置 mmdb
func (b *BaseApi) WafGeoDBExtract(c *gin.Context) {
	var req wafGeoDBReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	file, err := wafGeoDBName(req.Name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	dir, err := wafGeoDir()
	if err != nil {
		wafFailErr(c, err)
		return
	}
	cs := wafFindContainers()
	if len(cs) == 0 || cs[0].Image == "" {
		wafBad(c, "没找到 openresty 容器/镜像，无法提取")
		return
	}
	image := cs[0].Image
	target := filepath.Join(dir, file)
	tmp := target + ".new"
	_ = os.Remove(tmp)
	inImage := "/usr/local/openresty/1pwaf/data/geo/" + file
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "cat", image, inImage)
	out, err := os.Create(tmp)
	if err != nil {
		wafFailErr(c, err)
		return
	}
	cmd.Stdout = out
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	out.Close()
	if runErr != nil {
		_ = os.Remove(tmp)
		wafBad(c, fmt.Sprintf("从镜像提取失败：%v %s", runErr, strings.TrimSpace(errBuf.String())))
		return
	}
	buf, err := os.ReadFile(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		wafFailErr(c, err)
		return
	}
	ok, reason, hasProv := wafMMDBCheck(buf)
	if !ok {
		_ = os.Remove(tmp)
		wafBad(c, "镜像里的文件校验失败："+reason)
		return
	}
	bak := ""
	if wafPathExists(target) {
		bak = wafGeoDBBackup(target)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		wafFailErr(c, err)
		return
	}
	res := gin.H{"saved": true, "name": req.Name, "source": "image:" + image,
		"size": len(buf), "has_province": hasProv, "backup": bak, "path": target}
	if req.Live {
		outTxt, w, err := wafReloadConf()
		res["reloaded"] = err == nil
		res["reload_output"] = outTxt
		if len(w) > 0 {
			res["warnings"] = w
		}
	}
	wafOKData(c, res)
}

// WafGeoDBFromURL POST /api/v2/waf-log/geo/db/url {name, url, convert, async, reload}
// 默认走后台任务（下载 + 可能的 6~10 分钟转换），返回后前端轮询 /geo/db/job
func (b *BaseApi) WafGeoDBFromURL(c *gin.Context) {
	var req wafGeoDBReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	file, err := wafGeoDBName(req.Name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	u := strings.TrimSpace(req.URL)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		wafBad(c, "地址必须以 http:// 或 https:// 开头")
		return
	}
	dir, err := wafGeoDir()
	if err != nil {
		wafFailErr(c, err)
		return
	}
	convert := true
	if req.Convert != nil {
		convert = *req.Convert
	}
	async := true
	if req.Async != nil {
		async = *req.Async
	}

	if async {
		j := wafGeoJobBegin(req.Name)
		if j == nil {
			wafBad(c, "该库已有更新任务在运行，请等待完成")
			return
		}
		go wafGeoJobRunURL(j, dir, file, req.Name, u, req.Mirror, convert, req.Live)
		wafOKData(c, gin.H{"ok": true, "async": true, "name": req.Name, "state": "running",
			"msg": "任务已启动，请轮询 /waf-log/geo/db/job?name=" + req.Name})
		return
	}

	// 同步模式（小文件 / API 调试用）
	j := wafGeoJobBegin(req.Name)
	if j == nil {
		wafBad(c, "该库已有更新任务在运行，请等待完成")
		return
	}
	wafGeoJobRunURL(j, dir, file, req.Name, u, req.Mirror, convert, req.Live)
	if j.State == "error" {
		wafBad(c, j.Err)
		return
	}
	wafOKData(c, j.Result)
}

// WafGeoDBRestore POST /api/v2/waf-log/geo/db/restore {name}
func (b *BaseApi) WafGeoDBRestore(c *gin.Context) {
	var req wafGeoDBReq
	if err := c.ShouldBindJSON(&req); err != nil {
		wafBad(c, err.Error())
		return
	}
	file, err := wafGeoDBName(req.Name)
	if err != nil {
		wafBad(c, err.Error())
		return
	}
	dir, err := wafGeoDir()
	if err != nil {
		wafFailErr(c, err)
		return
	}
	target := filepath.Join(dir, file)
	baks, _ := filepath.Glob(target + ".bak.*")
	if len(baks) == 0 {
		wafBad(c, "没有可用备份")
		return
	}
	sort.Strings(baks)
	latest := baks[len(baks)-1]
	if err := copyFile(latest, target); err != nil {
		wafFailErr(c, err)
		return
	}
	outTxt, w, err := wafReloadConf()
	res := gin.H{"saved": true, "name": req.Name, "restored_from": latest,
		"reloaded": err == nil, "reload_output": outTxt}
	if len(w) > 0 {
		res["warnings"] = w
	}
	wafOKData(c, res)
}
