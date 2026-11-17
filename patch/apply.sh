#!/usr/bin/env bash
# 把 WAF 日志补丁应用到 1Panel v2.x 源码树（release-2.5.0 及同结构版本）
#
# 设计原则：只【新增】文件，不修改任何现有源码，幂等、易回滚。
#   - agent/router/ro_waf_log.go 用 init() 追加进 RouterGroupApp，无需改 common.go / entry.go
#   - frontend/src/routers/modules/waf-log.ts 被 import.meta.glob 自动收集，无需改 router.ts
#   - agent/go.mod 已含 github.com/glebarez/go-sqlite，无需加依赖
#
# 用法：
#   ./apply.sh /path/to/1Panel              # 应用补丁
#   ./apply.sh /path/to/1Panel --remove     # 移除补丁（还原为官方源码）

set -euo pipefail

PATCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-}"
ACTION="${2:-apply}"

if [[ -z "$SRC" || ! -d "$SRC" ]]; then
    echo "用法: $0 <1Panel 源码目录> [--remove]" >&2
    exit 1
fi

for marker in agent/go.mod frontend/package.json frontend/src/routers/router.ts agent/router/entry.go; do
    if [[ ! -f "$SRC/$marker" ]]; then
        echo "错误：$SRC 不像是 1Panel v2 源码树（缺少 $marker）" >&2
        exit 1
    fi
done

FILES=(
    "agent/app/api/v2/waf_log.go"
    "agent/app/api/v2/waf_log_extra.go"
    "agent/app/api/v2/waf_conf.go"
    "agent/app/api/v2/waf_state.go"
    "agent/app/api/v2/waf_rule.go"
    "agent/app/api/v2/waf_site.go"
    "agent/app/api/v2/waf_bw.go"
    "agent/app/api/v2/waf_block.go"
    "agent/app/api/v2/waf_html.go"
    "agent/app/api/v2/waf_overview.go"
    "agent/app/api/v2/waf_geo.go"
    "agent/app/api/v2/waf_geo_db.go"
    "agent/app/api/v2/waf_mmdb_conv.go"
    "agent/app/api/v2/waf_rule_form.go"
    "agent/app/api/v2/waf_map.go"
    "agent/app/api/v2/waf_monitor.go"
    "agent/app/api/v2/waf_geo_city.go"
    "agent/app/api/v2/waf_mod_update.go"
    "core/constant/common_waf_patch.go"
    "agent/router/ro_waf_log.go"
    "frontend/src/api/modules/waf-log.ts"
    "frontend/src/routers/modules/waf-log.ts"
    "frontend/src/routers/modules/waf-monitor.ts"
    "frontend/src/views/waf-log/index.vue"
    "frontend/src/views/waf-log/overview.vue"
    "frontend/src/views/waf-log/echart.vue"
    "frontend/src/views/waf-log/block.vue"
    "frontend/src/views/waf-log/site.vue"
    "frontend/src/views/waf-log/site-detail.vue"
    "frontend/src/views/waf-log/custom.vue"
    "frontend/src/views/waf-log/setting.vue"
    "frontend/src/views/waf-log/blackwhite.vue"
    "frontend/src/views/waf-log/geo-panel.vue"
    "frontend/src/views/waf-log/cdn-panel.vue"
    "frontend/src/views/waf-log/geo-db.vue"
    "frontend/src/views/waf-log/rule-inline.vue"
    "frontend/src/views/waf-log/monitor.vue"
    "frontend/src/views/waf-log/maps/world.json"
    "frontend/src/views/waf-log/maps/china.json"
    "frontend/src/views/waf-log/flat.css"
    "frontend/src/views/setting/about/mod-upgrade.vue"
    "lua/location_restrict.lua"
)

# 这些是【覆盖官方已有文件】而非新增文件：apply 前备份，--remove 时还原，
# 绝不能像新增文件那样直接 rm（否则整站 echarts 图表会崩）。
OVERWRITE_FILES=(
    "frontend/src/utils/echarts.ts"
    "frontend/src/views/setting/about/index.vue"
    "frontend/src/components/system-upgrade/upgrade/index.vue"
)

if [[ "$ACTION" == "--remove" ]]; then
    for f in "${FILES[@]}"; do
        rm -f "$SRC/$f"
        echo "  - $f"
    done
    for f in "${OVERWRITE_FILES[@]}"; do
        if [[ -f "$SRC/$f.wafbak" ]]; then
            mv -f "$SRC/$f.wafbak" "$SRC/$f"
            echo "  ~ $f （已还原官方原版）"
        else
            echo "  ~ $f （没有备份，保持现状不动）"
        fi
    done
    echo "已移除补丁文件，源码树恢复原状。"
    exit 0
fi

if [[ "$ACTION" != "apply" ]]; then
    echo "未知参数: $ACTION（只支持 --remove）" >&2
    exit 1
fi

for f in "${FILES[@]}"; do
    mkdir -p "$(dirname "$SRC/$f")"
    cp -f "$PATCH_DIR/$f" "$SRC/$f"
    echo "  + $f"
done

for f in "${OVERWRITE_FILES[@]}"; do
    mkdir -p "$(dirname "$SRC/$f")"
    if [[ ! -f "$SRC/$f.wafbak" ]]; then
        cp -f "$SRC/$f" "$SRC/$f.wafbak"
    fi
    cp -f "$PATCH_DIR/$f" "$SRC/$f"
    echo "  ~ $f （已覆盖，原版备份为 $f.wafbak）"
done

echo
echo "补丁已应用到 $SRC"
echo

# GeoIP 结构转换需要 github.com/maxmind/mmdbwriter（Go 侧建库），
# agent 自带 github.com/oschwald/maxminddb-golang 用于读取，无需再加。
GM="$SRC/agent/go.mod"
if [[ -f "$GM" ]] && ! grep -q "maxmind/mmdbwriter" "$GM"; then
    if grep -q "^require ($" "$GM"; then
        sed -i '0,/^require ($/s//require (\n\tgithub.com\/maxmind\/mmdbwriter v1.2.0/' "$GM"
    else
        printf '\nrequire github.com/maxmind/mmdbwriter v1.2.0\n' >> "$GM"
    fi
    echo "  + go.mod: 已加入 github.com/maxmind/mmdbwriter v1.2.0"
fi

echo
echo "注意："
echo "  1. 不用改 go.mod：agent/go.mod 已有 github.com/glebarez/go-sqlite（纯 Go，兼容 CGO_ENABLED=0）"
echo "  2. 不用改现有源码：路由靠 init() 追加，前端路由靠 modules/*.ts 自动收集"
echo "  3. core 会把 /api/v2/* 通配转发到本地 agent，所以 core 代码也不用改"
echo "  4. 但前端静态资源是 embed 进 1panel-core 的，必须重新构建 core 二进制"
echo "  5. 下一步：./tools/dev/build.sh $SRC            （只构建）"
echo "             ./tools/dev/build.sh $SRC --replace  （构建 + 备份 + 替换 + 重启）"
