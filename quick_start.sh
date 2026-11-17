#!/usr/bin/env bash
# 1Panel Mod —— 一键安装 / 回滚
#
#   curl -fsSL https://raw.githubusercontent.com/crossgg/1panel-mod/main/quick_start.sh | sudo bash
#   curl -fsSL .../quick_start.sh | sudo bash -s -- --version v2.5.1-mod.1
#   curl -fsSL .../quick_start.sh | sudo bash -s -- --mirror https://v4.gh-proxy.org/
#   sudo bash /opt/1panel-mod/current/install.sh --rollback
#
# 流程：检测系统与面板版本 → 查 Release → 下载对应架构产物 → 校验 SHA256
#      → 解压到 /opt/1panel-mod/releases/<tag>-<arch> → 调用随包 install.sh
# 失败时 install.sh 自带回滚；本脚本只删除自己创建的临时下载目录。
set -euo pipefail

REPO="${REPO:-crossgg/1panel-mod}"
BASE_DIR="/opt/1panel-mod"
API_BASE="https://api.github.com/repos/${REPO}"
UPSTREAM_TAG="v2.5.1"

VERSION=""
MIRROR=""
FORCE=0
AUTO_MIRROR=1
ACTION="install"
INSTALL_ARGS=()
MIRRORS=(
    "https://v4.gh-proxy.org/"
    "https://gh-proxy.com/"
    "https://ghfast.top/"
    "https://ghproxy.net/"
)

log()  { printf '\033[1;34m[1panel-mod]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
用法: quick_start.sh [选项]

  --version <tag>      指定 Mod Release tag（默认按本机 1Panel 版本自动选）
  --repo <owner/repo>  覆盖仓库地址（也可用环境变量 REPO）
  --mirror <prefix>    指定加速前缀，支持 https://xxx/ 或含 {url} 的模板
  --no-mirror          只用直连，不自动回退镜像
  --with-city          安装时同时启用城市级地区限制 Lua 补丁
  --no-lua             明确不写城市补丁（默认）
  --force              跳过 1Panel 版本守卫（不推荐）
  --rollback           回滚最近一次安装
  --uninstall          回滚并移除菜单节点与 Lua 补丁
  -h, --help           显示帮助

私有仓库可用环境变量 GITHUB_TOKEN 传入 token。
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    VERSION="${2:-}"; shift 2 ;;
        --repo)       REPO="${2:-}"; API_BASE="https://api.github.com/repos/${REPO}"; shift 2 ;;
        --mirror)     MIRROR="${2:-}"; shift 2 ;;
        --no-mirror)  AUTO_MIRROR=0; shift ;;
        --force)      FORCE=1; INSTALL_ARGS+=("--force"); shift ;;
        --with-city)  INSTALL_ARGS+=("--with-city"); shift ;;
        --no-lua)     INSTALL_ARGS+=("--no-lua"); shift ;;
        --rollback)   ACTION="rollback"; shift ;;
        --uninstall)  ACTION="uninstall"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) die "未知参数: $1（用 --help 查看用法）" ;;
    esac
done

# ---------------------------------------------------------------- 回滚 / 卸载
if [[ "$ACTION" != "install" ]]; then
    [[ -f "${BASE_DIR}/current/install.sh" ]] || die "找不到 ${BASE_DIR}/current/install.sh，无法${ACTION}"
    exec bash "${BASE_DIR}/current/install.sh" "--${ACTION}"
fi

[[ $EUID -eq 0 ]] || die "请用 root 执行（curl ... | sudo bash）"

for bin in curl tar sha256sum python3; do
    command -v "$bin" >/dev/null 2>&1 || die "缺少 ${bin}，请先安装"
done

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "暂不支持架构 $(uname -m)（目前只提供 amd64 / arm64）" ;;
esac
log "架构：${ARCH} · 仓库：${REPO}"

# ---------------------------------------------------------------- 前置检查
# 全新安装由官方脚本负责；本补丁只在已安装的 1Panel 上覆盖
if [[ ! -f /usr/local/bin/1panel-core || ! -f /usr/local/bin/1panel-agent ]]; then
    echo "未检测到已安装的 1Panel（/usr/local/bin/1panel-core / 1panel-agent）。"
    echo "本补丁不提供全新安装。请先执行官方安装："
    echo '  bash -c "$(curl -sSL https://resource.1panel.pro/v2/quick_start.sh)"'
    echo "装好后到面板「应用商店」安装 OpenResty，再重新运行本脚本。"
    exit 1
fi

# 版本守卫由产物内 install.sh 统一负责；这里只读取本机官方版本用于「选对 Release」
PANEL_VER=""
pctl="$(command -v 1pctl || true)"
if [[ -n "$pctl" ]]; then
    PANEL_VER="$($pctl version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
if [[ -n "$PANEL_VER" ]]; then
    log "本机 1Panel 版本：${PANEL_VER}"
else
    PANEL_VER="$UPSTREAM_TAG"
    warn "读不到 1pctl version，按默认 ${PANEL_VER} 选版本；install.sh 仍会做最终守卫"
fi

# ---------------------------------------------------------------- 查询 Release
TMP="$(mktemp -d /tmp/1panel-mod.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

AUTH=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

# ---------------------------------------------------------------- 选择匹配的 Mod 版本
# 优先读仓库根 SUPPORTED.json；索引不可用/无匹配时，按 "<官方版本>-mod.*" 前缀扫描 Releases。
MOD_TAG="$VERSION"   # --version 显式指定时跳过自动选择
if [[ -z "$MOD_TAG" ]]; then
    SUP_BASE="https://raw.githubusercontent.com/${REPO}/main/SUPPORTED.json"
    sup_urls=("$SUP_BASE")
    if [[ $AUTO_MIRROR -eq 1 ]]; then
        for m in "${MIRRORS[@]}"; do sup_urls+=("${m}${SUP_BASE}"); done
    fi
    for u in "${sup_urls[@]}"; do
        if curl -fsSL --connect-timeout 10 --max-time 25 ${AUTH[@]+"${AUTH[@]}"} "$u" -o "$TMP/SUPPORTED.json" 2>/dev/null; then break; fi
    done
    if [[ -s "$TMP/SUPPORTED.json" ]] && [[ $(head -c 1 "$TMP/SUPPORTED.json") == "{" ]]; then
        MOD_TAG="$(python3 - "$TMP/SUPPORTED.json" "$PANEL_VER" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
want = sys.argv[2]
c = [r for r in d.get("releases", []) if want in r.get("upstream", [])]
def k(r):
    p = r.get("mod", "").split("-mod.")
    return (p[0], int(p[1]) if len(p) > 1 and p[1].isdigit() else 0)
print(sorted(c, key=k)[-1]["mod"] if c else "")
PYX
)" || MOD_TAG=""
    fi
    if [[ -z "$MOD_TAG" ]]; then
        curl -fsSL --connect-timeout 10 --max-time 30 ${AUTH[@]+"${AUTH[@]}"} \
            "${API_BASE}/releases?per_page=100" -o "$TMP/releases.json" 2>/dev/null || true
        MOD_TAG="$(python3 - "$TMP/releases.json" "$PANEL_VER" <<'PYX'
import json, sys
try: d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception: d = []
pref = sys.argv[2] + "-mod."
c = [r.get("tag_name", "") for r in d if isinstance(r, dict) and r.get("tag_name", "").startswith(pref)]
def k(t):
    n = t[len(pref):]
    return int(n) if n.isdigit() else 0
print(sorted(c, key=k)[-1] if c else "")
PYX
)" || MOD_TAG=""
    fi
fi
if [[ -z "$MOD_TAG" ]]; then
    die "当前 1Panel ${PANEL_VER} 暂无对应的 Mod 版本。请查看 https://github.com/${REPO}/releases，或用 --version <tag> 指定"
fi
log "选用 Mod 版本：${MOD_TAG}"

if [[ -n "$VERSION" ]]; then
    api_url="${API_BASE}/releases/tags/${VERSION}"
else
    api_url="${API_BASE}/releases/tags/${MOD_TAG}"
fi
log "查询 Release：${api_url}"
if ! curl -fsSL --connect-timeout 10 --max-time 30 ${AUTH[@]+"${AUTH[@]}"} "$api_url" -o "$TMP/release.json"; then
    die "查询 Release 失败。可能是网络不通、仓库私有（需 GITHUB_TOKEN）或尚未发布 Release；也可用 --version <tag> 重试"
fi

parsed="$(python3 - "$TMP/release.json" "$ARCH" <<'PY'
import json, re, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    sys.exit("Release JSON 解析失败: %s" % e)
arch = sys.argv[2]
tag = d.get("tag_name") or ""
assets = d.get("assets") or []
pat = re.compile(r"^1panel-waf-.*-linux-" + re.escape(arch) + r"\.tar\.gz$")
tar = [a for a in assets if pat.match(a.get("name", ""))]
if not tar:
    sys.exit("该 Release 没有 %s 架构的产物" % arch)
t = tar[0]
sums_name = t["name"][:-7] + ".SHA256SUMS"
sums = [a for a in assets if a.get("name") == sums_name]
print(tag)
print(t.get("browser_download_url") or "")
print(sums[0].get("browser_download_url") if sums else "")
print((t.get("digest") or "").replace("sha256:", ""))
PY
)" || die "解析 Release 产物失败"
mapfile -t lines <<<"$parsed"
TAG="${lines[0]:-}"
PKG_URL="${lines[1]:-}"
SUMS_URL="${lines[2]:-}"
DIGEST="${lines[3]:-}"
[[ -n "$TAG" && -n "$PKG_URL" ]] || die "Release 里没有可用的产物地址"
log "目标版本：${TAG}"

# ---------------------------------------------------------------- 下载（直连优先 + 镜像回退）
fetch() {
    local url="$1" out="$2" cands=() c m
    if [[ -n "$MIRROR" ]]; then
        if [[ "$MIRROR" == *"{url}"* ]]; then
            cands=("${MIRROR//\{url\}/$url}")
        else
            cands=("${MIRROR%/}/${url}")
        fi
        cands+=("$url")
    else
        cands=("$url")
        if [[ $AUTO_MIRROR -eq 1 ]]; then
            for m in "${MIRRORS[@]}"; do cands+=("${m}${url}"); done
        fi
    fi
    for c in "${cands[@]}"; do
        log "下载：${c}"
        if curl -fsSL --connect-timeout 10 --max-time 900 ${AUTH[@]+"${AUTH[@]}"} -o "$out" "$c"; then
            return 0
        fi
        warn "失败，换下一个地址"
    done
    return 1
}

asset_name="${PKG_URL##*/}"
if [[ -n "$DIGEST" && -f "$PWD/$asset_name" ]]; then
    actual="$(sha256sum "$PWD/$asset_name" | awk '{print $1}')"
    if [[ "$actual" == "$DIGEST" ]]; then
        cp -f "$PWD/$asset_name" "$TMP/pkg.tar.gz"
        log "本地包 $asset_name 校验通过，跳过下载"
    else
        warn "本地包校验不通过，重新下载"
        fetch "$PKG_URL" "$TMP/pkg.tar.gz" || die "产物下载失败"
    fi
else
    fetch "$PKG_URL" "$TMP/pkg.tar.gz" || die "产物下载失败"
fi
if [[ -n "$SUMS_URL" ]]; then
    fetch "$SUMS_URL" "$TMP/SHA256SUMS" || warn "校验文件下载失败，将只做 tar 完整性检查"
fi

# ---------------------------------------------------------------- 校验与解压
tar -tzf "$TMP/pkg.tar.gz" >/dev/null || die "tar.gz 完整性检查失败"
safe_tag="${TAG//\//_}"
REL_DIR="${BASE_DIR}/releases/${safe_tag}-${ARCH}"
mkdir -p "$REL_DIR"
tar -xzf "$TMP/pkg.tar.gz" --strip-components=1 -C "$REL_DIR"
[[ -f "$REL_DIR/install.sh" && -f "$REL_DIR/1panel-core" && -f "$REL_DIR/1panel-agent" ]] \
    || die "产物内容不完整（缺少 install.sh 或二进制）"

if [[ -f "$TMP/SHA256SUMS" ]]; then
    cp -f "$TMP/SHA256SUMS" "$REL_DIR/SHA256SUMS"
    ( cd "$REL_DIR" && sha256sum -c SHA256SUMS ) || die "SHA256 校验失败，已停止安装"
    log "SHA256 校验通过"
else
    warn "未做 SHA256 校验"
fi

ln -sfn "$REL_DIR" "${BASE_DIR}/current"
log "产物已就绪：${REL_DIR}"

# ---------------------------------------------------------------- 交给 install.sh
bash "$REL_DIR/install.sh" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}

log "完成。面板版本标识：$(cat "$REL_DIR/MOD_VERSION" 2>/dev/null || echo "$TAG")"
if [[ -t 0 ]] && command -v 1pctl >/dev/null 2>&1; then
    log "当前面板登录信息："
    1pctl user-info 2>/dev/null || warn "读取失败，可手动执行 sudo 1pctl user-info"
else
    log "查看登录信息：sudo 1pctl user-info"
fi
log "回滚：sudo bash ${BASE_DIR}/current/install.sh --rollback"
log "卸载：sudo bash ${BASE_DIR}/current/install.sh --uninstall"
