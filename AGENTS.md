# AGENTS.md — AI / 维护者速读指南

> 给 AI 助手和后续维护者：**动代码前先读本文件 + `patch/manifest.yaml`**。
> 本仓库是 1Panel v2.5.1 社区版的**非官方功能补丁**，产物是重新编译的
> `1panel-core` / `1panel-agent` 两个二进制。

---

## 0. 一句话定位

官方 1Panel v2 社区版没有付费版才有的 WAF / 网站监控页面。本仓库用「**只新增文件 +
覆盖 3 个前端文件 + 覆盖 1 个 go.mod 依赖**」的方式，把功能补进官方源码树，
再用 CI 重新编译出可分发的二进制。不触碰任何授权校验逻辑。

- 上游：`1Panel-dev/1Panel` tag `v2.5.1`（GPL-3.0，全文见仓库根 `LICENSE`）
- 编译环境：Go `1.27.3`、Node `22`、`CGO_ENABLED=0`、Vite `build:pro`
- 目标平台：`linux/amd64`、`linux/arm64`（CI matrix 并行，两个都成功才发布）
- **Tag 规则**：`v<官方版本>-mod.<N>`；`main` 单主线，旧基线靠 tag 冻结，不轻易开 branch

---

## 1. 目录结构（方案 B）

```
.
├── .github/workflows/build.yml   CI：checkout 官方 tag → apply → 前端 → 交叉编译 → Release
├── .gitignore                    排除本地工作区/临时产物/archive
├── README.md                     人读文档（功能、安装、FAQ、许可）
├── AGENTS.md                     本文件（AI 速读）
├── SUPPORTED.json                ★ 官方版本 → Mod 版本 / 架构 索引（三处脚本共用）
├── quick_start.sh                下载器：按本机版本选 Release → 校验 → 解压 → 调 install.sh
├── install.sh                    产物内安装器：备份 → 换二进制 → 菜单 → 回滚
├── docs/                         界面截图
├── patch/                        ★ 补丁本体（apply.sh 的相对根）
│   ├── apply.sh                  幂等应用 / --remove 还原
│   ├── manifest.yaml             ★ 机器可读清单：每个文件 kind/depends_on/check/risk
│   ├── agent/  core/  frontend/  lua/   与官方源码树同构的补丁文件
│   └── scripts/                  HideMenu 注入、路由追加等一次性脚本
├── tools/
│   ├── check_upstream.sh         ★ 上游发新版时先跑它
│   └── dev/                      调试/验证/构建/部署脚本（不参与发布产物）
└── archive/                      历史遗留文件，已 .gitignore 排除，不入库
```

**路径约定**：`patch/` 下的 `agent/ core/ frontend/ lua/` 与官方源码树**同路径**，
`apply.sh` 直接 `cp` 过去；`PATCH_DIR` 是 `apply.sh` 自身所在目录，所以移动 `patch/`
整个目录不会破坏清单，但**移动内部文件必须同步改 `apply.sh` 的 `FILES`**。

---

## 2. 补丁怎么生效（改代码前必须理解）

| 机制 | 位置 | 说明 |
|---|---|---|
| 路由注入 | `patch/agent/router/ro_waf_log.go` | 用 `init()` 追加进 `RouterGroupApp`；依赖官方 `router/entry.go` 的 `!xpack && !enterprise` build tag |
| 前端路由自动收集 | `patch/frontend/src/routers/modules/*.ts` | 依赖官方 `router.ts` 的 `import.meta.glob('./modules/*.ts')` |
| API 转发 | `patch/frontend/src/api/modules/waf-log.ts` | core 把非 `/api/v2/core` 的请求通配转发到本地 agent |
| 前端路由白名单 | `patch/core/constant/common_waf_patch.go` | 往 `WebUrlMap` / `DynamicRoutes` 追加 `/waf-log/*`、`/waf-monitor/*`；**漏了会在刷新页面时被安全入口拦成 "Access Temporarily Unavailable"** |
| 菜单节点 | `patch/scripts/*_menu_patch.py` | 侧边栏走 `core.db` 的 `settings.HideMenu` 快照，节点靠 `label == route.name` 识别；用户重置菜单顺序后会丢，需重跑 |
| 城市级限制 | `patch/lua/location_restrict.lua` | 写进 openresty **挂载卷** `data/lua/`，并前置 `conf/waf.conf` 的 `lua_package_path`；不改容器镜像 |
| 前端资源 embed | 官方 `core/cmd/server/web` | **改了任何前端文件必须重新构建 `1panel-core`**，只换 agent 不会生效 |

`apply.sh --remove` 会删除 `FILES` 里的新增文件，并从 `.wafbak` 还原
`OVERWRITE_FILES`（3 个官方前端文件 + 手动维护的 `echarts.ts` 等）。
**覆盖官方文件绝不能直接 `rm`**——`echarts.ts` 被删会让整站图表崩掉。

---

## 3. 上游升级决策树（本文件的核心）

官方发新 tag 时按这个顺序，**不要凭记忆猜**：

1. 取干净源码：`git clone --depth 1 --branch <新tag> https://github.com/1Panel-dev/1Panel.git /tmp/1p-new`
2. 跑 `tools/check_upstream.sh /tmp/1p-new <新tag>`，读输出：
   - `BLOCK` = 必须改（覆盖文件被官方重写、依赖符号消失、新增路径被占用）
   - `WARN`  = 可能要改（Go / Node / ECharts 版本变化）
   - `OK`    = 无需改
3. 按 `patch/manifest.yaml` 的 `overwrite` 段逐个处理：从**新官方版**重新取基线，
   重新合并我们的注入标记（`EffectScatterChart` / `ModUpgrade` / `mod-upgrade-warn`），
   并更新 `apply.sh` 的 `OVERWRITE_FILES` 行为描述。
4. 按 `depends_on` 处理消失的官方符号：`ro_waf_log.go` 的 build tag、
   `router.ts` 的 glob、`common.go` 的 `WebUrlMap`、`helper.go` 的转发、
   `echarts.ts` 的按需注册列表。
5. 检查 Go / Node / ECharts 大版本；`go.mod` 的 `github.com/maxmind/mmdbwriter`
   仍由 `apply.sh` 注入。
6. `bash patch/apply.sh /tmp/1p-new` → 前端 `npm ci && npm run build:pro`
   （**必须先 `rm -rf core/cmd/server/web/assets`**）→ 分别编译 agent/core。
7. 回归清单：接口冒烟（`tools/dev/smoke_v3.py`、`smoke_v4.py`）、
   无头截图（`tools/dev/check_v4.js`，**只截内容区 clip x≥180**）、
   中国地图等比、0 个 JS 错误、城市状态卡、Mod 更新弹窗。
8. 更新 `SUPPORTED.json`（追加新官方基线条目）、`manifest.yaml` 的 `upstream.tag`、
   `README.md` 的版本号与前置条件、`build.yml` 的 `upstream_tag` 默认值、
   `install.sh` / `quick_start.sh` 的默认版本兜底。
9. 出包：打 `v<新官方版本>-mod.1` 或 workflow_dispatch 手填 `mod_version`；CI 的 `meta` job
   统一算出 tag_name 与产物内 `MOD_VERSION`，两个架构都成功才发 Release。

**判断规则**：
- 只有 `OK` → 可以直接出包；
- 有 `WARN` 无 `BLOCK` → 跑构建 + 截图回归，通过即可出包；
- 有 `BLOCK` → 必须重新合并，禁止直接改版本号出包。
- 官方小版本（如 v2.5.2）通常只影响 3 个覆盖文件；大版本（v2.6+）
  默认视为不兼容，需重新评估整个补丁。

---

## 4. 已知硬坑（血泪清单，改代码前先扫一遍）

1. **ECharts 6.x `preserveAspect`**：`applyPreserveAspect` 用
   `getShallow('preserveAspect', true)`，第二参数是 `ignoreParent` **不是默认值**；
   不显式写 `preserveAspect: true` 时四边固定会把地图非等比拉伸。
   中国地图用 `aspectScale: 0.85` + `zoom: 1`；**不要用 `layoutCenter/layoutSize`**
   （与水平 visualMap 组合会抛 `Cannot read properties of null (reading '0')`）。
2. **水平 visualMap 必须带 `seriesIndex: 0`**，否则推断空 data 的 map series 会报同样的错。
3. **echarts/core 按需注册**：新增图表类型必须在 `frontend/src/utils/echarts.ts`
   里 `use(...)` 注册，否则 series 被静默丢弃（底图在、点不显示）。
4. **`site_req_logs.status_code` 恒为 0**，真实状态码在 `status_code_id → status_codes.db`；
   4xx/5xx 统计、日志列、筛选全都要走字典。
5. **`site_req_logs.time` 是 REAL 浮点时间戳**，Scan 到 `int64` 会全表 skip；
   `localtime` 驱动返回 `time.Time`，要 `sql.NullString` + 重新格式化。
6. **字典分散在多个 .db 文件**，SQLite 单连接不能跨库子查询；
   IP/URI/方法筛选必须先读字典到内存再拼 `IN (?)`。
7. **`wafInClause` 在 `waf_log.go` 已有同名函数（返回 2 值）**，别重复定义；
   空 id 列表要显式 `1 = 0`，否则筛选会退化成全表。
8. **1pwaf 的 `data/sites/<key>/rules/` 里出现任何非 `.json` 文件会让
   `init_by_lua` 整体失败，WAF 静默放行所有请求**。备份一律写到
   `<1pwaf>-backup/`，绝不落在 `data/` 里。
9. **监控采集需要全局 `conf/monitor.json.state` 与站点 `monitor.json.state` 同时 on**，
   只开一个不产生数据；写配置后必须 reload。
10. **镜像自带 GeoIP.mmdb 不含 `city` 字段**，城市限制必须先下载
    `GeoLite2-City.mmdb` 并自动转换成 1pwaf 扁平结构。
11. **`geo/db/job` 的 `elapsed`**：running 时 `End` 是零值，
    `End.Sub(Start)` 会溢出成巨大负数，必须用 `time.Since(Start)`。
12. **GitHub 直连会「响应头 200 但 body 挂死」**，只在 `cli.Do` 失败时换候选会一直
    卡到 Client.Timeout(30min)；必须给每个候选做完整下载 + 停滞看门狗。
13. **fullPage 截图假象**：侧栏是 `position: fixed`，全页截图只画第一屏，
    下方内容看起来像侵占侧栏。验证脚本一律 `clip {x:180,...}`。
14. **同名官方函数/变量**：新增 Go 文件前先 `grep` 同包已有符号。
15. **前端覆盖文件**：`about/index.vue`、`upgrade/index.vue`、`echarts.ts`
    都是覆盖官方版，`--remove` 必须还原而不是删除。

---

## 5. 安装 / 更新 / 城市补丁的心智模型

- **两层脚本**（和官方一致）：`quick_start.sh` 是下载器，`install.sh` 在 Release 产物内。
  二者**不重复**；版本守卫只在 `install.sh` 做。
- **不做全新安装**：机器上没有 `1panel-core`/`1panel-agent` 时，脚本打印官方
  `quick_start.sh` 命令后退出。正确顺序：官方装 1Panel → 应用商店装 OpenResty →
  跑本仓库一键脚本。端口/账号/密码/安全入口全部沿用官方安装结果，我们**不生成也不改**。
- **城市补丁默认不启用**：`install.sh` 在 TTY 询问 `y/N`，管道场景默认跳过，
  显式 `--with-city` 才写；`install.sh --with-city` 可事后补打。
  面板「全局设置 → 地区访问限制」有三步状态卡（OpenResty / Lua 补丁 / GeoIP city）
  和独立的「应用城市补丁」按钮（**不要把它绑到 `cityRules.length`**，否则没有 City 库时
  按钮永远不显示，形成死循环）。
- **双更新检测**：官方社区版走官方 OSS（保持原样，升级抽屉加了「会覆盖补丁」警告）；
  Mod 版只在点击时查 `crossgg/1panel-mod` 最新 Release，只提示去仓库看命令，
  不在面板内自动升级、没有任何定时轮询。

---

## 6. 构建与验证

```bash
# 应用补丁
bash patch/apply.sh /path/to/1Panel
bash patch/apply.sh /path/to/1Panel --remove      # 还原（覆盖文件从 .wafbak 恢复）

# 本地构建（Linux，Go 1.27.3 / Node 22）
cd /path/to/1Panel/frontend && npm ci && rm -rf ../core/cmd/server/web/assets && npm run build:pro
cd ../agent && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o ../build/1panel-agent ./cmd/server/main.go
cd ../core && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o ../build/1panel-core ./cmd/server/main.go

# 上游兼容检查
tools/check_upstream.sh /path/to/clean-1Panel <tag>

# 回归（真机需要 TMPDIR 可写、Puppeteer 用内容区裁剪截图）
tools/dev/smoke_v3.py
tools/dev/smoke_v4.py
TMPDIR=<可写目录> node tools/dev/check_v4.js
```

CI 的 matrix 是 `amd64` + `arm64`，`GOOS=linux`、`CGO_ENABLED=0`，
每个架构产出 `1panel-agent` + `1panel-core` 两个二进制，打成
`1panel-waf-<tag>-linux-<arch>.tar.gz` + `.SHA256SUMS`。

---

## 7. AI 操作守则

1. 改任何文件前先查 `patch/manifest.yaml`：是 `new` 还是 `overwrite`，
   有没有 `depends_on` 官方锚点。
2. 新增 Go 文件先 `grep` 同包符号；新增 Vue 组件先确认 ECharts 组件已注册。
3. 改了 `patch/frontend/**` 就必须重建 core（前端资源 embed），只换 agent 无效。
4. 改了覆盖官方的前端文件，同步检查 `--remove` 的还原路径与 `.wafbak` 逻辑。
5. 改了接口/路由，同步 `patch/agent/router/ro_waf_log.go`、`core/constant/common_waf_patch.go`
   （新页面路径）、HideMenu 注入脚本、`frontend/src/api/modules/waf-log.ts`。
6. 不要动官方授权校验、不要加定时/后台轮询任务、不要往 `1pwaf/data/`
   里放非 `.json` 文件。
7. 任何改动都要跑一遍「构建 → 真机部署 → 接口冒烟 → 截图 0 报错」，
   并把结论写进 `.workbuddy/memory/YYYY-MM-DD.md`。
