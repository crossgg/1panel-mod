import io

p = "<1Panel 源码目录>/agent/router/ro_waf_log.go"
s = io.open(p, encoding="utf-8").read()
anchor = '\t\twafLogRouter.POST("/rule/op", api.WafRuleOp)\n'
add = '\t\twafLogRouter.POST("/rule/compile", api.WafRuleCompile)\n'
if "/rule/compile" in s:
    print("rule/compile route already present")
elif anchor in s:
    s = s.replace(anchor, anchor + add, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("rule/compile route added")
else:
    print("ANCHOR NOT FOUND")
