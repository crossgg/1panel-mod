import { Layout } from '@/routers/constant';

// 网站监控（独立一级菜单，对齐官方 xpack 的「网站监控」）
// 页面内用 el-tabs 分：概览 / 访问统计 / 趋势统计 / 请求日志 / 网站列表 / 设置

const wafMonitorRouter = {
    sort: 6,
    path: '/waf-monitor',
    name: 'WafMonitor-Menu',
    component: Layout,
    redirect: '/waf-monitor/index',
    meta: {
        icon: 'p-waf-3',
        title: '网站监控',
    },
    children: [
        {
            path: '/waf-monitor/index',
            name: 'WafMonitor',
            component: () => import('@/views/waf-log/monitor.vue'),
            meta: {
                icon: 'p-waf-3',
                title: '网站监控',
            },
        },
    ],
};

export default wafMonitorRouter;
