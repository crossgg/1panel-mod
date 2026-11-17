import io

p = "<1Panel 源码目录>/agent/router/ro_waf_log.go"
s = io.open(p, encoding="utf-8").read()
anchor = '\t\twafLogRouter.GET("/overview/map", api.WafAttackMap)\n'
add = """		// 网站监控（独立一级菜单）
		wafLogRouter.GET("/monitor/sites", api.WafMonitorSites)
		wafLogRouter.GET("/monitor/overview", api.WafMonitorOverview)
		wafLogRouter.GET("/monitor/trend", api.WafMonitorTrend)
		wafLogRouter.GET("/monitor/dims", api.WafMonitorDims)
		wafLogRouter.GET("/monitor/logs", api.WafMonitorLogs)
		wafLogRouter.GET("/monitor/config", api.WafMonitorConfig)
		wafLogRouter.POST("/monitor/config", api.WafMonitorConfigSave)
		wafLogRouter.POST("/monitor/state", api.WafMonitorState)
"""
if "/monitor/sites" in s:
    print("monitor routes already present")
elif anchor in s:
    s = s.replace(anchor, anchor + add, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("monitor routes added")
else:
    print("ANCHOR NOT FOUND")
