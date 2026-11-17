#!/usr/bin/env bash
# 1Panel v2.5.1 社区版 WAF 补丁 —— 一键安装 / 回滚
#
#   sudo bash install.sh                 安装（下载产物解压后在本目录执行）
#   sudo bash install.sh --rollback     回滚到最近一次安装前的二进制与配置
#   sudo bash install.sh --uninstall    回滚并移除侧边栏菜单节点与 Lua 补丁
#   sudo bash install.sh --force        跳过版本守卫
#   sudo bash install.sh --with-city    安装时同时启用城市级地区限制 Lua 补丁
#   sudo bash install.sh --no-lua       明确不写 Lua 补丁
#   sudo bash install.sh --city-only    只补打城市级 Lua 补丁（不动二进制，可事后执行）
#   sudo bash install.sh --no-menu      不注入侧边栏菜单
#
# 前置：已用官方脚本安装 1Panel v2.5.1 社区版，并在应用商店装好 OpenResty。
# 城市补丁默认不启用（会改 openresty 的 waf.conf 并 reload），TTY 下会询问。
# 所有写操作都会先备份到 /opt/1panel-waf-backup/<时间戳>/，失败自动回滚。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/opt/1panel-waf-backup"
CORE_BIN="/usr/local/bin/1panel-core"
AGENT_BIN="/usr/local/bin/1panel-agent"
PANEL_DB="/opt/1panel/db/core.db"
UPSTREAM_TAG="v2.5.1"
LUA_MARK="/usr/local/openresty/1pwaf/data/lua/?.lua;"

MODE="install"
DO_LUA=0
DO_MENU=1
FORCE=0
LUA_EXPLICIT=0
for arg in "$@"; do
    case "$arg" in
        --rollback) MODE="rollback" ;;
        --uninstall) MODE="uninstall" ;;
        --force) FORCE=1 ;;
        --with-city) DO_LUA=1; LUA_EXPLICIT=1 ;;
        --no-lua) DO_LUA=0; LUA_EXPLICIT=1 ;;
        --city-only) MODE="city"; DO_LUA=1; LUA_EXPLICIT=1 ;;
        --no-menu) DO_MENU=0 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "未知参数: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '\033[1;34m[waf-patch]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 执行（sudo bash install.sh）"
command -v python3 >/dev/null 2>&1 || warn "没找到 python3，菜单注入与配置修正会跳过"

latest_backup() { ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1 || true; }

# ---------------------------------------------------------------- 回滚 / 卸载
rollback() {
    local b="${1:-}"
    [[ -z "$b" ]] && b="$(latest_backup)"
    [[ -n "$b" && -d "$b" ]] || die "找不到可回滚的备份（$BACKUP_ROOT）"
    log "从 $b 回滚"
    systemctl stop 1panel-core 1panel-agent 2>/dev/null || true
    [[ -f "$b/1panel-core" ]]  && install -m 755 "$b/1panel-core"  "$CORE_BIN"
    [[ -f "$b/1panel-agent" ]] && install -m 755 "$b/1panel-agent" "$AGENT_BIN"
    [[ -f "$b/core.db" ]]      && cp -f "$b/core.db" "$PANEL_DB"
    if [[ -f "$b/waf.conf" && -f "$b/waf_conf_path" ]]; then
        cp -f "$b/waf.conf" "$(cat "$b/waf_conf_path")"
    fi
    [[ -f "$b/monitor.json" && -f "$b/monitor_path" ]] && cp -f "$b/monitor.json" "$(cat "$b/monitor_path")"
    [[ -f "$b/global.json"  && -f "$b/global_path"  ]] && cp -f "$b/global.json"  "$(cat "$b/global_path")"
    if [[ -f "$b/mod_version" ]]; then
        mkdir -p /opt/1panel/1panel-mod
        cp -f "$b/mod_version" /opt/1panel/1panel-mod/VERSION
    elif [[ -f "$b/no_mod_version" ]]; then
        rm -f /opt/1panel/1panel-mod/VERSION
    fi
    [[ -f "$b/lua_existed"  && -f "$b/lua_path"     ]] || true
    if [[ -f "$b/lua_path" ]]; then
        local lp; lp="$(cat "$b/lua_path")"
        if [[ -f "$b/lua_existed" ]]; then
            cp -f "$b/location_restrict.lua" "$lp"
        else
            rm -f "$lp"   # 只删除本次安装新建的单个文件
        fi
    fi
    systemctl start 1panel-agent 1panel-core 2>/dev/null || true
    reload_openresty
    log "回滚完成"
}

reload_openresty() {
    local c
    c="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'openresty' | head -1 || true)"
    if [[ -n "$c" ]]; then
        docker exec "$c" nginx -t >/dev/null 2>&1 && docker exec "$c" nginx -s reload >/dev/null 2>&1 || warn "openresty reload 失败，请手动检查"
    else
        warn "没找到 openresty 容器，跳过 reload"
    fi
}

print_install_hint() {
    echo "未检测到已安装的 1Panel（$CORE_BIN / $AGENT_BIN）。"
    echo "本补丁只支持在已安装的 1Panel v2.5.1 社区版上覆盖，不提供全新安装。"
    echo "请先执行官方安装："
    echo '  bash -c "$(curl -sSL https://resource.1panel.pro/v2/quick_start.sh)"'
    echo "装好后到面板「应用商店」安装 OpenResty，再重新运行本脚本。"
}

print_city_hint() {
    warn "城市级地区限制补丁未应用：这台机器还没有 OpenResty / 1pwaf 数据目录。"
    warn "请到面板「应用商店」安装 OpenResty，然后任选一种方式补打："
    warn "  sudo bash ${BASE_DIR:-/opt/1panel-mod/current}/install.sh --city-only"
    warn "  或在面板「全局设置 → 地区访问限制」点「应用城市补丁」"
}

# 城市补丁：写挂载卷 lua/ + 幂等改 waf.conf + reload；可被 install / --city-only 复用
apply_city_patch() {
    local wd wc lp bdir
    wd="$(find /opt/1panel/apps/openresty -maxdepth 5 -type d -path '*/1pwaf/data' 2>/dev/null | head -1 || true)"
    if [[ -z "$wd" || ! -d "$wd/conf" ]]; then
        print_city_hint
        return 0
    fi
    [[ -f "$DIR/location_restrict.lua" ]] || { warn "产物里缺少 location_restrict.lua，跳过"; return 0; }
    command -v python3 >/dev/null 2>&1 || { warn "缺少 python3，跳过 Lua 补丁"; return 0; }
    wc="$wd/conf/waf.conf"
    lp="$wd/lua/location_restrict.lua"
    if [[ ! -f "$wc" ]]; then
        warn "没找到 $wc，跳过 Lua 补丁（可在面板里点『应用城市补丁』）"
        return 0
    fi
    bdir="${BACKUP:-$BACKUP_ROOT/city-$(date +%s)}"
    mkdir -p "$bdir"
    cp -a "$wc" "$bdir/waf.conf" && echo "$wc" > "$bdir/waf_conf_path"
    echo "$lp" > "$bdir/lua_path"
    [[ -f "$lp" ]] && cp -a "$lp" "$bdir/location_restrict.lua" && touch "$bdir/lua_existed"
    mkdir -p "$(dirname "$lp")"
    install -m 644 "$DIR/location_restrict.lua" "$lp"
    python3 - "$wc" "$LUA_MARK" <<'PYX'
import io, sys
p, mark = sys.argv[1], sys.argv[2]
s = io.open(p, encoding="utf-8").read()
if mark not in s:
    lines = s.split("\n")
    for i, line in enumerate(lines):
        if "lua_package_path" in line and "1pwaf/lib/?.lua" in line:
            lines[i] = line.replace('"', '"' + mark, 1)
            break
    else:
        print("  !! waf.conf 未找到 lua_package_path，跳过")
        sys.exit(0)
    io.open(p, "w", encoding="utf-8").write("\n".join(lines))
    print("  waf.conf lua_package_path 已前置补丁目录")
PYX
    reload_openresty
    log "城市级地区限制 Lua 补丁已写入挂载卷（容器重建不丢）"
}

if [[ "$MODE" == "rollback" || "$MODE" == "uninstall" ]]; then
    rollback
    if [[ "$MODE" == "uninstall" ]]; then
        log "移除侧边栏菜单节点"
        python3 - <<'PY' 2>/dev/null || warn "菜单节点移除失败（可忽略）"
import json, sqlite3
DB = "/opt/1panel/db/core.db"
con = sqlite3.connect(DB)
row = con.execute("select value from settings where key='HideMenu'").fetchone()
if row:
    menu = json.loads(row[0])
    menu = [x for x in menu if x.get("label") not in ("WafLog-Menu", "WafMonitor-Menu")]
    con.execute("update settings set value=? where key='HideMenu'", (json.dumps(menu, ensure_ascii=False),))
    con.commit()
con.close()
PY
    fi
    exit 0
fi

# ---------------------------------------------------------------- 安装前检查
if [[ "$MODE" == "city" ]]; then
    apply_city_patch
    exit 0
fi

[[ -f "$CORE_BIN" && -f "$AGENT_BIN" ]] || { print_install_hint; exit 1; }
[[ -f "$DIR/1panel-core" && -f "$DIR/1panel-agent" ]] || die "当前目录缺少 1panel-core / 1panel-agent（请先解压 release 产物）"
# 产物内 SUPPORTED.json 是「本产物支持哪些官方版本」的唯一来源；
# 老产物没有它时回退到 UPSTREAM_TAG 文件，再回退到脚本默认值。
supported=""
if [[ -f "$DIR/SUPPORTED.json" ]] && command -v python3 >/dev/null 2>&1; then
    supported="$(python3 - "$DIR/SUPPORTED.json" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
vs = []
for r in d.get("releases", []):
    vs += r.get("upstream", [])
print(" ".join(sorted(set(vs))))
PYX
)" || supported=""
fi
if [[ -z "$supported" && -f "$DIR/UPSTREAM_TAG" ]]; then
    supported="$(cat "$DIR/UPSTREAM_TAG")"
fi
[[ -z "$supported" ]] && supported="$UPSTREAM_TAG"

if [[ $FORCE -eq 0 ]] && command -v 1pctl >/dev/null 2>&1; then
    cur="$(1pctl version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ -n "$cur" ]] && ! grep -qw -- "$cur" <<<"$supported"; then
        die "面板版本 $cur 不在本产物支持范围（支持：$supported）；请下载对应版本的 Release，或加 --force 强制安装（不建议）"
    fi
    [[ -n "$cur" ]] && log "版本检查通过：$cur（支持：$supported）"
fi

# 城市补丁默认不启用；TTY 下询问，管道（curl | bash）默认跳过
if [[ $LUA_EXPLICIT -eq 0 && -t 0 ]]; then
    ans=""
    read -r -p "是否启用城市级地区限制 Lua 补丁？会改 openresty 的 waf.conf 并 reload [y/N] " ans || true
    case "${ans,,}" in
        y|yes) DO_LUA=1 ;;
    esac
fi
[[ $DO_LUA -eq 0 ]] && log "城市补丁默认不启用；事后可用 --city-only 或面板按钮补打"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BACKUP_ROOT/$STAMP"
mkdir -p "$BACKUP"
cp -a "$CORE_BIN"  "$BACKUP/1panel-core"
cp -a "$AGENT_BIN" "$BACKUP/1panel-agent"
[[ -f "$PANEL_DB" ]] && cp -a "$PANEL_DB" "$BACKUP/core.db"
if [[ -f /opt/1panel/1panel-mod/VERSION ]]; then
    cp -a /opt/1panel/1panel-mod/VERSION "$BACKUP/mod_version"
else
    : > "$BACKUP/no_mod_version"
fi
echo "$BACKUP" > "$BACKUP_ROOT/latest"
log "已备份到 $BACKUP"

ROLLBACK_DONE=0
on_err() {
    if [[ $ROLLBACK_DONE -eq 0 ]]; then
        warn "安装出错，自动回滚"
        rollback "$BACKUP" || true
    fi
}
trap on_err ERR

# ---------------------------------------------------------------- 1. 二进制
systemctl stop 1panel-core 1panel-agent 2>/dev/null || true
install -m 755 "$DIR/1panel-core"  "$CORE_BIN"
install -m 755 "$DIR/1panel-agent" "$AGENT_BIN"
systemctl start 1panel-agent
sleep 3
systemctl start 1panel-core
sleep 3
systemctl is-active 1panel-agent >/dev/null || die "1panel-agent 未启动"
systemctl is-active 1panel-core  >/dev/null || die "1panel-core 未启动"
log "二进制已替换，服务已启动"

# Mod 版本标识：面板「Mod 更新」读取它作为当前版本
if [[ -f "$DIR/MOD_VERSION" ]]; then
    mkdir -p /opt/1panel/1panel-mod
    install -m 644 "$DIR/MOD_VERSION" /opt/1panel/1panel-mod/VERSION
    log "Mod 版本：$(cat "$DIR/MOD_VERSION")"
fi

# ---------------------------------------------------------------- 2. 侧边栏菜单
if [[ $DO_MENU -eq 1 ]] && command -v python3 >/dev/null 2>&1 && [[ -f "$PANEL_DB" ]]; then
    [[ -f "$DIR/waf_menu_patch.py" ]]     && python3 "$DIR/waf_menu_patch.py"     >/dev/null
    [[ -f "$DIR/monitor_menu_patch.py" ]] && python3 "$DIR/monitor_menu_patch.py" >/dev/null
    log "侧边栏菜单节点已注入（WAF / 网站监控）"
else
    warn "跳过菜单注入"
fi

# ---------------------------------------------------------------- 3. 日志默认值
WAF_DATA="$(find /opt/1panel/apps/openresty -maxdepth 5 -type d -path '*/1pwaf/data' 2>/dev/null | head -1 || true)"
if [[ -n "$WAF_DATA" && -d "$WAF_DATA/conf" ]] && command -v python3 >/dev/null 2>&1; then
    MP="$WAF_DATA/conf/monitor.json"
    GP="$WAF_DATA/conf/global.json"
    [[ -f "$MP" ]] && cp -a "$MP" "$BACKUP/monitor.json" && echo "$MP" > "$BACKUP/monitor_path"
    [[ -f "$GP" ]] && cp -a "$GP" "$BACKUP/global.json"  && echo "$GP" > "$BACKUP/global_path"
    python3 - "$MP" "$GP" <<'PY'
import json, os, sys
mp, gp = sys.argv[1], sys.argv[2]
if os.path.isfile(mp):
    d = json.load(open(mp, encoding="utf-8"))
    d.setdefault("log", {})
    if int(d["log"].get("maxSize") or 1) < 100:
        d["log"]["maxSize"] = 100
        open(mp, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False, indent=2))
        print("  monitor.json log.maxSize -> 100")
if os.path.isfile(gp):
    d = json.load(open(gp, encoding="utf-8"))
    d.setdefault("log", {})
    if int(d["log"].get("maxSize") or 1) < 500:
        d["log"]["maxSize"] = 500
        open(gp, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False, indent=2))
        print("  global.json log.maxSize -> 500")
PY
    log "日志单库上限已校正（WAF 500MB / 监控 100MB）"
else
    warn "没找到 1pwaf 数据目录，跳过日志默认值校正"
fi

# ---------------------------------------------------------------- 4. 城市 Lua 补丁
if [[ $DO_LUA -eq 1 ]]; then
    apply_city_patch
fi

# ---------------------------------------------------------------- 5. 校验
# 端口由官方安装随机生成，绝对不能硬编码 10086：本补丁只替换二进制，不改任何端口/配置。
# 端口从 1pctl user-info 动态解析；HTTP 探测只做提示，不再是触发回滚的硬条件。
panel_port=""
if command -v 1pctl >/dev/null 2>&1; then
    panel_port="$(1pctl user-info 2>/dev/null | grep -oE ':[0-9]{2,5}/' | head -1 | tr -d ':/' || true)"
fi
[[ -z "$panel_port" ]] && panel_port="10086"
if ! systemctl is-active 1panel-core >/dev/null 2>&1 || ! systemctl is-active 1panel-agent >/dev/null 2>&1; then
    die "1panel-core / 1panel-agent 未处于运行状态，已回滚"
fi
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${panel_port}/" || true)"
if [[ "$code" == "200" ]]; then
    log "面板 HTTP 校验通过（端口 ${panel_port}）"
else
    warn "HTTP 探测返回 ${code}（端口 ${panel_port}）；服务已正常启动，若端口非默认值请以 sudo 1pctl user-info 为准"
fi

ROLLBACK_DONE=1
trap - ERR
log "完成。备份目录：$BACKUP"
log "回滚：sudo bash install.sh --rollback"
if [[ -t 0 ]] && command -v 1pctl >/dev/null 2>&1; then
    log "当前面板登录信息（端口/账号/密码沿用官方安装结果）："
    1pctl user-info 2>/dev/null || warn "读取失败，可手动执行 sudo 1pctl user-info"
else
    log "查看登录信息：sudo 1pctl user-info（端口/账号/密码沿用官方安装结果）"
fi
