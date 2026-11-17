import io

p = "<1Panel 源码目录>/agent/router/ro_waf_log.go"
s = io.open(p, encoding="utf-8").read()
anchor = '\t\twafLogRouter.POST("/rule/compile", api.WafRuleCompile)\n'
add = '\t\twafLogRouter.GET("/overview/map", api.WafAttackMap)\n'
if "/overview/map" in s:
    print("overview/map already present")
elif anchor in s:
    s = s.replace(anchor, anchor + add, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("overview/map added")
else:
    print("ANCHOR NOT FOUND")
