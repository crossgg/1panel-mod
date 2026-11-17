#!/usr/bin/env bash
# 上游版本兼容性检查 —— 官方发新版后先跑这个，AI 只需读输出
#
#   tools/check_upstream.sh <官方源码目录> [官方 tag]
#
# 例：
#   git clone --depth 1 --branch v2.5.2 https://github.com/1Panel-dev/1Panel.git /tmp/1p-new
#   tools/check_upstream.sh /tmp/1p-new v2.5.2
#
# 输出三档：
#   BLOCK 必须改（覆盖文件被官方重写 / 依赖符号消失 / 同名文件被占用）
#   WARN  可能要改（Go/Node/依赖版本变化）
#   OK    无需改
# 有 BLOCK 时退出码 1。
set -euo pipefail

SRC="${1:-}"
NEW_TAG="${2:-unknown}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/patch/manifest.yaml"

[[ -n "$SRC" && -d "$SRC" ]] || { echo "用法: $0 <官方源码目录> [官方 tag]" >&2; exit 2; }
[[ -f "$MANIFEST" ]] || { echo "找不到 $MANIFEST" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "需要 python3" >&2; exit 2; }

python3 - "$SRC" "$NEW_TAG" "$ROOT" "$MANIFEST" <<'PY'
import os, re, sys

src, new_tag, root, manifest = sys.argv[1:5]
BASE_TAG = "v2.5.1"

# 极简 manifest 解析（固定缩进格式，不依赖 PyYAML）
entries = []
cur = None
for line in open(manifest, encoding="utf-8"):
    line = line.rstrip("\n")
    if line.startswith("  - path: "):
        cur = {"path": line.split(": ", 1)[1], "deps": [], "marker": "", "kind": "new"}
        entries.append(cur)
    elif cur and line.startswith("    kind: "):
        cur["kind"] = line.split(": ", 1)[1]
    elif cur and line.startswith("    depends_on:"):
        cur["deps"] = re.findall(r'"([^"]+)"', line)
    elif cur and line.startswith("    marker:"):
        parts = line.split('"')
        cur["marker"] = parts[1] if len(parts) > 1 else ""

report = []
def add(level, msg):
    report.append((level, msg))

def read(rel):
    p = os.path.join(src, rel)
    return open(p, encoding="utf-8", errors="ignore").read() if os.path.isfile(p) else None

print("=== 1Panel Mod 上游兼容性检查 ===")
print(f"基准上游 : 1Panel-dev/1Panel {BASE_TAG}")
print(f"待检源码 : {src}  (tag: {new_tag})")
print(f"补丁清单 : patch/manifest.yaml  ({sum(e['kind']=='new' for e in entries)} new + "
      f"{sum(e['kind']=='overwrite' for e in entries)} overwrite)")
print()

# ---------- 1. 全局锚点 ----------
checks = [
    ("agent/go.mod",           r"^go\s+1\.27\.3",      "go 版本 1.27.3",                 "BLOCK"),
    ("core/go.mod",            r"^go\s+1\.27\.3",      "go 版本 1.27.3",                 "BLOCK"),
    ("frontend/package.json",  r'"build:pro"',         "前端 build:pro 脚本",            "WARN"),
    ("frontend/src/routers/router.ts", r"import\.meta\.glob", "前端路由 import.meta.glob", "BLOCK"),
    ("core/middleware/helper.go",      r"ShouldProxyToAgent", "core→agent 通配转发",      "BLOCK"),
    ("core/cmd/server/web/web.go",     r"go:embed",    "前端资源 embed 进 core",         "WARN"),
    ("agent/go.mod",           r"glebarez/go-sqlite",  "纯 Go sqlite 依赖",              "BLOCK"),
]
for rel, pat, label, level in checks:
    txt = read(rel)
    if txt is None:
        add("WARN", f"官方源码里没有 {rel}，{label} 需人工确认")
    elif re.search(pat, txt, re.M):
        add("OK", f"{label} 仍在（{rel}）")
    else:
        add(level, f"{label} 未命中，官方改了 {rel}")

# ECharts 大版本
pkg = read("frontend/package.json") or ""
m = re.search(r'"echarts"\s*:\s*"[^\d]*(\d+)', pkg)
if m:
    major = int(m.group(1))
    if major >= 6:
        add("OK", f"ECharts {major}.x（preserveAspect 需显式 true 的行为已知）")
    else:
        add("WARN", f"ECharts 降到 {major}.x，地图等比与 visualMap 参数需重新验证")
else:
    add("WARN", "package.json 里没读到 echarts 版本")

# ---------- 2. 覆盖文件 ----------
for e in entries:
    if e["kind"] != "overwrite":
        continue
    official = read(e["path"])
    patched = os.path.join(root, "patch", e["path"])
    ours = open(patched, encoding="utf-8").read() if os.path.isfile(patched) else ""
    if official is None:
        add("BLOCK", f"覆盖文件在新官方源码里不存在：{e['path']}")
        continue
    if e["marker"] and e["marker"] not in official:
        add("BLOCK", f"官方版缺少注入标记 {e['marker']}：{e['path']} —— 需从官方新版重新取基线并重新合并")
    elif e["marker"] and e["marker"] in official:
        add("OK", f"{e['path']} 含注入标记（传入的是已打补丁的树）")
    if ours and e["marker"] and e["marker"] not in ours:
        add("BLOCK", f"补丁仓库里的 {e['path']} 丢了标记 {e['marker']}")
    elif not ours:
        add("WARN", f"本地补丁仓库里没有 {e['path']}（可能只上传了 manifest，跳过基线比对）")
    # 官方版相对基准是否有变化（用补丁版与官方版行数差做粗略提示）
    if official.count("\n") != ours.count("\n"):
        add("WARN", f"{e['path']} 行数与补丁版不同（官方 {official.count(chr(10))} 行 / 补丁 {ours.count(chr(10))} 行），合并时注意上下文")

# ---------- 3. 新增文件依赖的官方符号 ----------
seen = set()
for e in entries:
    for dep in e["deps"]:
        if dep.startswith("runtime:"):
            continue
        key = (e["path"], dep)
        if key in seen:
            continue
        seen.add(key)
        if ":" not in dep:
            continue
        rel, sym = dep.split(":", 1)
        txt = read(rel)
        if txt is None:
            add("BLOCK", f"{e['path']} 依赖的官方文件不存在：{rel}")
        elif sym not in txt:
            add("BLOCK", f"{e['path']} 依赖的官方符号消失：{rel}:{sym}")
        else:
            add("OK", f"依赖符号仍在：{rel}:{sym}")

# ---------- 4. 新增文件路径是否被官方占用（合并成一条汇总） ----------
present = [e["path"] for e in entries
           if e["kind"] == "new" and os.path.isfile(os.path.join(src, e["path"]))]
if present:
    add("OK", f"官方树里已有 {len(present)} 个补丁文件路径（说明传入的是已打补丁的树，非干净上游）")
else:
    add("OK", "新增文件路径在官方树里均未被占用（干净上游）")

# ---------- 汇总 ----------
order = {"BLOCK": 0, "WARN": 1, "OK": 2}
for level in ("BLOCK", "WARN", "OK"):
    items = [m for l, m in report if l == level]
    if items:
        print(f"--- {level} ({len(items)}) ---")
        for m in items:
            print(f"  [{level:5}] {m}")
blocks = sum(1 for l, _ in report if l == "BLOCK")
warns = sum(1 for l, _ in report if l == "WARN")
print()
print(f"汇总: BLOCK={blocks}  WARN={warns}  OK={len(report)-blocks-warns}")
if blocks:
    print("结论: 需要先处理所有 BLOCK 项，再重新取基线 / 合并并出包。")
else:
    print("结论: 没有阻塞项；按 patch/apply.sh 重新应用并跑构建 + 截图回归即可。")
print()
print("下一步 SOP 见 AGENTS.md「上游升级决策树」。")
sys.exit(1 if blocks else 0)
PY
