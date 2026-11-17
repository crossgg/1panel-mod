//go:build !xpack && !enterprise

package router

// WAF 日志路由（补丁文件，新增）
// 与 agent/router/entry.go 保持相同的 build tag，只在社区版构建中参与。
// 通过 init() 把自身追加进 RouterGroupApp，无需修改 agent/router/common.go 或 entry.go。
// Go 包级变量先初始化、再执行 init()，因此 append 会在 agent/init/router.Routers() 遍历之前完成。

import (
	v2 "github.com/1Panel-dev/1Panel/agent/app/api/v2"
	"github.com/gin-gonic/gin"
)

type WafLogRouter struct{}

func init() {
	RouterGroupApp = append(RouterGroupApp, &WafLogRouter{})
}

func (a *WafLogRouter) InitRouter(Router *gin.RouterGroup) {
	api := v2.ApiGroupApp.BaseApi
	wafLogRouter := Router.Group("waf-log")
	{
		wafLogRouter.GET("/diag", api.WafLogDiag)
		wafLogRouter.GET("/overview", api.WafLogOverview)
		wafLogRouter.GET("/stat", api.WafLogStat)
		wafLogRouter.GET("/sites", api.WafLogSites)
		wafLogRouter.GET("/rules", api.WafLogRules)
		wafLogRouter.GET("/list", api.WafLogList)
		wafLogRouter.GET("/sitelogs", api.WafLogSiteLogs)

		// 防护设置页用
		wafLogRouter.GET("/config", api.WafLogConfig)
		wafLogRouter.POST("/config", api.WafLogConfigSave)
		wafLogRouter.POST("/config/reload", api.WafLogConfigReload)
		wafLogRouter.POST("/state", api.WafState)
		wafLogRouter.GET("/raw", api.WafLogConfigRaw)
		wafLogRouter.POST("/raw", api.WafLogConfigRaw)

		// 网站设置页用
		wafLogRouter.GET("/site/list", api.WafSiteList)
		wafLogRouter.GET("/site/config", api.WafSiteConfig)
		wafLogRouter.POST("/site/config", api.WafSiteConfigSave)
		wafLogRouter.GET("/site/rule", api.WafSiteRuleGet)
		wafLogRouter.POST("/site/rule", api.WafSiteRuleSave)

		// 黑白名单页用
		wafLogRouter.GET("/bw/summary", api.WafBwSummary)
		wafLogRouter.GET("/bw/get", api.WafBwGet)
		wafLogRouter.POST("/bw/save", api.WafBwSave)
		wafLogRouter.POST("/bw/toggle", api.WafBwToggle)
		wafLogRouter.POST("/bw/import", api.WafBwImport)

		// 自定义规则页用
		wafLogRouter.GET("/rule/meta", api.WafRuleMeta)
		wafLogRouter.GET("/rule/all", api.WafRuleAll)
		wafLogRouter.POST("/rule/op", api.WafRuleOp)
		wafLogRouter.POST("/rule/compile", api.WafRuleCompile)
		wafLogRouter.GET("/overview/map", api.WafAttackMap)
		// 网站监控（独立一级菜单）
		wafLogRouter.GET("/monitor/sites", api.WafMonitorSites)
		wafLogRouter.GET("/monitor/overview", api.WafMonitorOverview)
		wafLogRouter.GET("/monitor/trend", api.WafMonitorTrend)
		wafLogRouter.GET("/monitor/dims", api.WafMonitorDims)
		wafLogRouter.GET("/monitor/logs", api.WafMonitorLogs)
		wafLogRouter.GET("/monitor/realtime", api.WafMonitorRealtime)
		wafLogRouter.GET("/monitor/config", api.WafMonitorConfig)
		wafLogRouter.POST("/monitor/config", api.WafMonitorConfigSave)
		wafLogRouter.POST("/monitor/state", api.WafMonitorState)

		// 封锁记录页用
		wafLogRouter.GET("/block/list", api.WafBlockList)
		wafLogRouter.POST("/block/remove", api.WafBlockRemove)
		wafLogRouter.POST("/block/add", api.WafBlockAdd)
		wafLogRouter.GET("/block/export", api.WafBlockExport)

		// 拦截页面自定义 + 日志导出/清空
		wafLogRouter.GET("/html/list", api.WafHtmlList)
		wafLogRouter.GET("/html/get", api.WafHtmlGet)
		wafLogRouter.POST("/html/save", api.WafHtmlSave)
		wafLogRouter.POST("/html/revert", api.WafHtmlRevert)
		wafLogRouter.GET("/log/export", api.WafLogExport)
		wafLogRouter.POST("/log/clear", api.WafLogClear)

		// 地区访问限制 / CDN 真实 IP 策略
		wafLogRouter.GET("/geo/options", api.WafGeoOptions)
		wafLogRouter.GET("/geo/cities", api.WafGeoCities)
		wafLogRouter.GET("/mod/version", api.WafModVersion)
		wafLogRouter.GET("/geo/city/status", api.WafGeoCityStatus)
		wafLogRouter.POST("/geo/city/patch", api.WafGeoCityPatch)
		wafLogRouter.GET("/policy", api.WafPolicyGet)
		wafLogRouter.POST("/policy", api.WafPolicySave)
		wafLogRouter.POST("/policy/reset", api.WafPolicyReset)
		wafLogRouter.GET("/geo/db", api.WafGeoDBInfo)
		wafLogRouter.GET("/geo/db/job", api.WafGeoDBJob)
		wafLogRouter.POST("/geo/db/extract", api.WafGeoDBExtract)
		wafLogRouter.POST("/geo/db/url", api.WafGeoDBFromURL)
		wafLogRouter.POST("/geo/db/restore", api.WafGeoDBRestore)
	}
}
