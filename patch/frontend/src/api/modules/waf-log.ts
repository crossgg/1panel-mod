import http from '@/api';

// baseURL 已包含 /api/v2；core 会把非 /api/v2/core 的请求通配转发到本地 agent

export const getWafLogDiag = () => http.get<any>('/waf-log/diag');

export const getWafLogStat = () => http.get<any>('/waf-log/stat');

export const getWafOverview = (params?: object) => http.get<any>('/waf-log/overview', params || {});

export const getWafLogSites = (kind?: string) => http.get<any>('/waf-log/sites', kind ? { kind } : {});

export const getWafLogRules = () => http.get<any>('/waf-log/rules');

export const getWafLogList = (params: object) => http.get<any>('/waf-log/list', params);

export const getWafLogSiteLogs = (params: object) => http.get<any>('/waf-log/sitelogs', params);

// ---------- 防护设置 ----------
export const getWafConfig = () => http.get<any>('/waf-log/config');

export const saveWafConfig = (data: object) => http.post<any>('/waf-log/config', data);

export const reloadWafConfig = () => http.post<any>('/waf-log/config/reload', {});
// 单个模块开关（官方 config/global/state / config/website/state 的等价物）
export const setWafState = (data: object) => http.post<any>('/waf-log/state', data);


export const getWafRaw = (file: string) => http.get<any>('/waf-log/raw', { file });

export const saveWafRaw = (data: object) => http.post<any>('/waf-log/raw', data);

// ---------- 网站设置 ----------
export const getWafSiteList = () => http.get<any>('/waf-log/site/list');

export const getWafSiteConfig = (key: string) => http.get<any>('/waf-log/site/config', { key });

export const saveWafSiteConfig = (data: object) => http.post<any>('/waf-log/site/config', data);

export const getWafSiteRule = (key: string, file: string) => http.get<any>('/waf-log/site/rule', { key, file });

export const saveWafSiteRule = (data: object) => http.post<any>('/waf-log/site/rule', data);

// ---------- 黑白名单 ----------
export const getWafBwSummary = () => http.get<any>('/waf-log/bw/summary');

export const getWafBwList = (kind: string) => http.get<any>('/waf-log/bw/get', { kind });

export const saveWafBw = (data: object) => http.post<any>('/waf-log/bw/save', data);

export const importWafBw = (data: object) => http.post<any>('/waf-log/bw/import', data);

// ---------- 自定义规则 ----------
// key 为空 = 全局规则库；传站点 key = 该站点自己的规则库
export const getWafRuleMeta = (params?: object) => http.get<any>('/waf-log/rule/meta', params || {});

export const getWafRuleAll = (params: object) => http.get<any>('/waf-log/rule/all', params);

export const opWafRule = (data: object) => http.post<any>('/waf-log/rule/op', data);

// 图形化表单（匹配对象 / 条件 / 内容 / 动作 / 状态码）→ 1pwaf 规则条目
// 拦截地图（近 N 天，按国家聚合）
export const getWafAttackMap = (params: object) => http.get<any>('/waf-log/overview/map', params);

export const compileWafRule = (data: object) => http.post<any>('/waf-log/rule/compile', data);

// ---------- 封锁记录 ----------
export const getWafBlockList = (params: object) => http.get<any>('/waf-log/block/list', params);

export const removeWafBlock = (data: object) => http.post<any>('/waf-log/block/remove', data);

export const addWafBlockIp = (data: object) => http.post<any>('/waf-log/block/add', data);

export const exportWafBlockUrl = '/api/v2/waf-log/block/export';

// ---------- 拦截页面 ----------
export const getWafHtmlList = () => http.get<any>('/waf-log/html/list');

export const getWafHtml = (name: string) => http.get<any>('/waf-log/html/get', { name });

export const saveWafHtml = (data: object) => http.post<any>('/waf-log/html/save', data);

export const revertWafHtml = (data: object) => http.post<any>('/waf-log/html/revert', data);

// ---------- 日志导出 / 清空 ----------
export const clearWafLog = () => http.post<any>('/waf-log/log/clear', {});

export const exportWafLogUrl = '/api/v2/waf-log/log/export';

// ---------- 地区访问限制 / CDN 策略 ----------
export const getWafGeoOptions = () => http.get<any>('/waf-log/geo/options');

export const getWafGeoCities = () => http.get<any>('/waf-log/geo/cities');

export const getWafGeoCityStatus = () => http.get<any>('/waf-log/geo/city/status');

export const applyWafGeoCityPatch = () => http.post<any>('/waf-log/geo/city/patch', {});

export const getWafPolicy = (params: object) => http.get<any>('/waf-log/policy', params);

export const saveWafPolicy = (data: object) => http.post<any>('/waf-log/policy', data);

export const resetWafPolicy = (data: object) => http.post<any>('/waf-log/policy/reset', data);

// ---------- IP 库维护 ----------
export const getWafGeoDb = () => http.get<any>('/waf-log/geo/db');

export const getWafGeoDbJob = (name: string) => http.get<any>('/waf-log/geo/db/job', { name });

export const getWafModVersion = (params: object) => http.get<any>('/waf-log/mod/version', params);

export const extractWafGeoDb = (data: object) => http.post<any>('/waf-log/geo/db/extract', data);

export const fromUrlWafGeoDb = (data: object) => http.post<any>('/waf-log/geo/db/url', data);

export const restoreWafGeoDb = (data: object) => http.post<any>('/waf-log/geo/db/restore', data);

// ---------- 网站监控 ----------
export const getWafMonSites = () => http.get<any>('/waf-log/monitor/sites');

export const getWafMonOverview = (params: object) => http.get<any>('/waf-log/monitor/overview', params);

export const getWafMonTrend = (params: object) => http.get<any>('/waf-log/monitor/trend', params);

export const getWafMonDims = (params: object) => http.get<any>('/waf-log/monitor/dims', params);

export const getWafMonLogs = (params: object) => http.get<any>('/waf-log/monitor/logs', params);

export const getWafMonRealtime = (params: object) => http.get<any>('/waf-log/monitor/realtime', params);

export const getWafMonConfig = (params: object) => http.get<any>('/waf-log/monitor/config', params);

export const saveWafMonConfig = (data: object) => http.post<any>('/waf-log/monitor/config', data);

export const saveWafMonState = (data: object) => http.post<any>('/waf-log/monitor/state', data);
