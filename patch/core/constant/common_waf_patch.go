package constant

// WAF 前端路由放行（补丁文件，新增）
//
// 背景：core 的 NoRoute 处理会调用 security.CanServeFrontendPath，
// 进而用 constant.WebUrlMap（精确匹配）+ constant.DynamicRoutes（正则）判断
// 该路径是否属于 SPA 前端路由。不在名单里的路径会被
// HandleNotSecurity 拦成 html/200.html（"Access Temporarily Unavailable"），
// 表现就是「点菜单能进、刷新就白屏/报错」。
//
// 官方 xpack 的 WAF 页面同样需要在 DynamicRoutes 里登记（见 `^/xpack/waf/websites/[^/]+$`），
// 这里用同包 init() 追加，不修改 common.go 原文。

func init() {
	for _, p := range []string{
		"/waf-log",
		"/waf-log/overview",
		"/waf-log/list",
		"/waf-log/block",
		"/waf-log/blackwhite",
		"/waf-log/site",
		"/waf-log/custom",
		"/waf-log/setting",
		"/waf-monitor",
		"/waf-monitor/index",
	} {
		WebUrlMap[p] = struct{}{}
	}
	DynamicRoutes = append(DynamicRoutes, `^/waf-log/[A-Za-z0-9_-]+$`)
	DynamicRoutes = append(DynamicRoutes, `^/waf-monitor(/index)?$`)
}
