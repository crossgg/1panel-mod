package v2

// 面板「Mod 版更新检测」（补丁文件，新增）
//
// 与官方社区版更新完全并列、互不干扰：
//   - 官方：GET /core/settings/upgrade → OSS 取 stable/latest，POST 会替换二进制（会覆盖补丁）
//   - Mod ：GET /waf-log/mod/version?check=1 → 按本机官方版本从 SUPPORTED.json 选匹配的
//           Mod tag，再查该 tag 的 Release；索引不可用时回退 /releases/latest
//
// 关键约束（按用户需求）：
//   - **只在用户点击「检查 Mod 更新」时**才发网络请求；页面加载/不带 check 参数只读本地版本
//   - **不在面板里执行升级**，只提示去仓库 Release 页查看更新命令
//   - 仓库尚未创建/未公开/网络不通时返回友好文案，不报 500
//   - 没有任何定时轮询

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	wafModRepo        = "crossgg/1panel-mod"
	wafModVersionFile = "/opt/1panel/1panel-mod/VERSION"
	wafModIndexURL    = "https://raw.githubusercontent.com/crossgg/1panel-mod/main/SUPPORTED.json"
)

type wafModAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type wafModRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	HTMLURL     string        `json:"html_url"`
	Assets      []wafModAsset `json:"assets"`
}

type wafModIndexEntry struct {
	Mod      string   `json:"mod"`
	Upstream []string `json:"upstream"`
}

type wafModIndex struct {
	Releases []wafModIndexEntry `json:"releases"`
}

// wafModUpstreamVersion 从 1pctl version 读本机官方版本（如 v2.5.1）
func wafModUpstreamVersion() string {
	bin := "/usr/local/bin/1pctl"
	if _, err := os.Stat(bin); err != nil {
		bin = "1pctl"
	}
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil && string(out) == "" {
		return ""
	}
	return regexp.MustCompile(`v\d+\.\d+\.\d+`).FindString(string(out))
}

// wafModSeq 取 v2.5.1-mod.12 里的 12，用于自然排序（避免字典序把 .10 排在 .9 前面）
func wafModSeq(tag string) int {
	i := strings.LastIndex(tag, "-mod.")
	if i < 0 {
		return 0
	}
	n, _ := strconv.Atoi(tag[i+len("-mod."):])
	return n
}

// wafModPickRelease 按本机官方版本从 SUPPORTED.json 选最新的 Mod tag
func wafModPickRelease(cli *http.Client, upstream string) string {
	if upstream == "" {
		return ""
	}
	req, err := http.NewRequest("GET", wafModIndexURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "1panel-waf-patch/1.0")
	resp, err := cli.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var idx wafModIndex
	if json.Unmarshal(raw, &idx) != nil {
		return ""
	}
	best := ""
	for _, r := range idx.Releases {
		for _, v := range r.Upstream {
			if v != upstream {
				continue
			}
			if best == "" || wafModSeq(r.Mod) > wafModSeq(best) ||
				(wafModSeq(r.Mod) == wafModSeq(best) && r.Mod > best) {
				best = r.Mod
			}
			break
		}
	}
	return best
}

// WafModVersion GET /api/v2/waf-log/mod/version?check=1
func (b *BaseApi) WafModVersion(c *gin.Context) {
	current := "unknown"
	if raw, err := os.ReadFile(wafModVersionFile); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			current = v
		}
	}
	out := gin.H{
		"repo":         wafModRepo,
		"repo_url":     "https://github.com/" + wafModRepo,
		"releases_url": "https://github.com/" + wafModRepo + "/releases",
		"current":      current,
		"checked":      false,
		"has_update":   false,
	}

	if c.Query("check") != "1" {
		wafOK(c, out)
		return
	}
	out["checked"] = true

	upstream := wafModUpstreamVersion()
	out["upstream"] = upstream

	cli := &http.Client{Timeout: 10 * time.Second}
	apiPath := "releases/latest"
	if tag := wafModPickRelease(cli, upstream); tag != "" {
		apiPath = "releases/tags/" + tag
		out["selected_tag"] = tag
	}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+wafModRepo+"/"+apiPath, nil)
	if err != nil {
		out["error"] = err.Error()
		wafOK(c, out)
		return
	}
	req.Header.Set("User-Agent", "1panel-waf-patch/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cli.Do(req)
	if err != nil {
		out["error"] = "检查失败：" + err.Error()
		wafOK(c, out)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 404 {
		if upstream != "" && apiPath != "releases/latest" {
			out["error"] = fmt.Sprintf("本机 1Panel %s 对应的 Mod 版本尚未发布 Release（%s）", upstream, wafModRepo)
		} else {
			out["error"] = "仓库尚未创建、未公开，或还没有发布过 Release（" + wafModRepo + "）"
		}
		wafOK(c, out)
		return
	}
	if resp.StatusCode != 200 {
		out["error"] = fmt.Sprintf("GitHub API 返回 HTTP %d", resp.StatusCode)
		wafOK(c, out)
		return
	}
	var rel wafModRelease
	if err := json.Unmarshal(raw, &rel); err != nil {
		out["error"] = "解析 Release 信息失败：" + err.Error()
		wafOK(c, out)
		return
	}
	out["latest"] = rel.TagName
	out["name"] = rel.Name
	out["published_at"] = rel.PublishedAt
	out["html_url"] = rel.HTMLURL
	out["notes"] = rel.Body
	out["assets"] = rel.Assets
	out["has_update"] = rel.TagName != "" && rel.TagName != current
	wafOK(c, out)
}
