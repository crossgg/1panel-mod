import { Layout } from '@/routers/constant';

// 新增文件即可：frontend/src/routers/router.ts 用 import.meta.glob('./modules/*.ts') 自动收集，
// Sidebar 从 menuList 生成菜单，无需修改任何现有文件。
// meta.title 直接写中文，vue-i18n 找不到对应 key 时会原样显示（不影响使用）。
//
// 注意：侧边栏走的是 HideMenu 快照，节点只认 label==route.name，
// 所以新增子页时必须同步往 core.db 的 settings.HideMenu 里加同名节点（本仓库有脚本）。
//
// 菜单顺序对齐官方 xpack（8 条路由）：
//   dashboard → stat → log → block → blackwhite → websites → websites/:id → global
// 本项目按 概览 → 拦截日志 → 封锁记录 → 黑白名单 → 网站设置 →（自定义规则）→ 全局设置 排列，
// 其中「自定义规则」是额外拆出来的独立页（官方合并在全局设置的第 3 个页签里）。

const wafLogRouter = {
    sort: 5,
    path: '/waf-log',
    name: 'WafLog-Menu',
    component: Layout,
    redirect: '/waf-log/overview',
    meta: {
        icon: 'p-waf-menu',
        title: 'WAF',
    },
    children: [
        {
            path: '/waf-log/overview',
            name: 'WafLogOverview',
            component: () => import('@/views/waf-log/overview.vue'),
            meta: {
                icon: 'p-waf-2',
                title: '概览',
            },
        },
        {
            path: '/waf-log/list',
            name: 'WafLog',
            component: () => import('@/views/waf-log/index.vue'),
            meta: {
                icon: 'p-waf-1',
                title: '拦截日志',
            },
        },
        {
            path: '/waf-log/block',
            name: 'WafLogBlock',
            component: () => import('@/views/waf-log/block.vue'),
            meta: {
                icon: 'p-waf-6',
                title: '封锁记录',
            },
        },
        {
            path: '/waf-log/blackwhite',
            name: 'WafLogBw',
            component: () => import('@/views/waf-log/blackwhite.vue'),
            meta: {
                icon: 'p-waf-4',
                title: '黑白名单',
            },
        },
        {
            path: '/waf-log/site',
            name: 'WafLogSite',
            component: () => import('@/views/waf-log/site.vue'),
            meta: {
                icon: 'p-waf-3',
                title: '网站设置',
            },
        },
        {
            path: '/waf-log/custom',
            name: 'WafLogRule',
            component: () => import('@/views/waf-log/custom.vue'),
            meta: {
                icon: 'p-waf-5',
                title: '自定义规则',
            },
        },
        {
            path: '/waf-log/setting',
            name: 'WafLogSetting',
            component: () => import('@/views/waf-log/setting.vue'),
            meta: {
                icon: 'p-setting-1',
                title: '全局设置',
            },
        },
    ],
};

export default wafLogRouter;
