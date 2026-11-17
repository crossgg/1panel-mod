import io
import re

p = "<1Panel 源码目录>/agent/router/ro_waf_log.go"
s = io.open(p, encoding="utf-8").read()
anchor = '\t\twafLogRouter.POST("/policy/reset", api.WafPolicyReset)\n'
old_block = (
    '\t\twafLogRouter.GET("/geo/db", api.WafGeoDBInfo)\n'
    '\t\twafLogRouter.POST("/geo/db/extract", api.WafGeoDBExtract)\n'
    '\t\twafLogRouter.POST("/geo/db/url", api.WafGeoDBFromURL)\n'
    '\t\twafLogRouter.POST("/geo/db/restore", api.WafGeoDBRestore)\n'
)
new_block = (
    '\t\twafLogRouter.GET("/geo/db", api.WafGeoDBInfo)\n'
    '\t\twafLogRouter.GET("/geo/db/job", api.WafGeoDBJob)\n'
    '\t\twafLogRouter.POST("/geo/db/extract", api.WafGeoDBExtract)\n'
    '\t\twafLogRouter.POST("/geo/db/url", api.WafGeoDBFromURL)\n'
    '\t\twafLogRouter.POST("/geo/db/restore", api.WafGeoDBRestore)\n'
)
if "/geo/db/job" in s:
    print("geo/db routes already present")
elif old_block in s:
    s = s.replace(old_block, new_block, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("geo/db routes upgraded (job route added)")
elif anchor in s:
    s = s.replace(anchor, anchor + new_block, 1)
    io.open(p, "w", encoding="utf-8").write(s)
    print("geo/db routes added")
else:
    print("ANCHOR NOT FOUND")

# 确保 agent/go.mod 里有 mmdbwriter（-mod=mod 构建时会自动补 go.sum）
gm = "<1Panel 源码目录>/agent/go.mod"
g = io.open(gm, encoding="utf-8").read()
if "mmdbwriter" in g:
    print("go.mod already has mmdbwriter")
else:
    m = re.search(r"^require \($", g, re.M)
    if m:
        g = g[:m.end()] + "\n\tgithub.com/maxmind/mmdbwriter v1.2.0" + g[m.end():]
    else:
        g = g.rstrip("\n") + "\n\nrequire github.com/maxmind/mmdbwriter v1.2.0\n"
    io.open(gm, "w", encoding="utf-8").write(g)
    print("go.mod: mmdbwriter added")
