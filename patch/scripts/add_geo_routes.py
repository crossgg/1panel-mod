import io
import os

p = "<1Panel 源码目录>/agent/router/ro_waf_log.go"
s = io.open(p, encoding="utf-8").read()
anchor = '\t\twafLogRouter.POST("/log/clear", api.WafLogClear)\n'
add = (
    '\n\t\t// 地区访问限制 / CDN 真实 IP 策略\n'
    '\t\twafLogRouter.GET("/geo/options", api.WafGeoOptions)\n'
    '\t\twafLogRouter.GET("/policy", api.WafPolicyGet)\n'
    '\t\twafLogRouter.POST("/policy", api.WafPolicySave)\n'
    '\t\twafLogRouter.POST("/policy/reset", api.WafPolicyReset)\n'
)
if "/geo/options" in s:
    print("routes already present")
elif anchor in s:
    s = s.replace(anchor, anchor + add, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("routes added")
else:
    print("ANCHOR NOT FOUND")
