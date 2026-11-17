<template>
    <div class="waf-monitor" v-loading="loading">
        <el-card shadow="never" class="mb">
            <div class="top-bar">
                <div class="left">
                    <span class="page-title">网站监控</span>
                    <el-select v-model="site" size="small" style="width: 240px" @change="loadAll">
                        <el-option v-for="s in sites" :key="s.key" :value="s.key" :label="s.key" />
                    </el-select>
                    <el-tag size="small" :type="monitorEffective ? 'success' : 'warning'" style="margin-left: 8px">
                        {{ monitorEffective ? '监控已开启' : monitorHint }}
                    </el-tag>
                </div>
                <div class="right">
                    <el-button size="small" @click="loadAll">{{ $t('commons.button.refresh') }}</el-button>
                    <span class="sw-label">全局</span>
                    <el-switch v-model="globalState" active-value="on" inactive-value="off" size="small" @change="toggleGlobal" />
                    <span class="sw-label">当前站点</span>
                    <el-switch v-model="siteState" active-value="on" inactive-value="off" size="small" @change="toggleState" />
                </div>
            </div>
        </el-card>

        <el-tabs v-model="tab">
            <!-- ================= 概览 ================= -->
            <el-tab-pane label="概览" name="overview">
                <div class="wf-flat">
                    <section class="wf-panel" style="margin-bottom: 12px">
                        <div class="wf-kpis wf-8">
                            <div class="wf-kpi" v-for="m in metricCards" :key="m.key">
                                <div class="k">{{ m.label }}</div>
                                <div class="v wf-small">{{ m.value }}</div>
                            </div>
                        </div>
                    </section>

                    <div class="wf-grid">
                        <section class="wf-panel">
                            <h3 class="wf-title">
                                访客地图（{{ mapDays }}日）
                                <span class="wf-extra">覆盖 {{ (ov.countries || []).length }} 个国家/地区</span>
                            </h3>
                            <div class="wf-seg">
                                <el-radio-group v-model="mapMode" size="small">
                                    <el-radio-button value="world">世界</el-radio-button>
                                    <el-radio-button value="china">中国</el-radio-button>
                                </el-radio-group>
                                <el-radio-group v-model="mapMetric" size="small">
                                    <el-radio-button value="source">来源</el-radio-button>
                                    <el-radio-button value="count">数量</el-radio-button>
                                </el-radio-group>
                                <el-radio-group v-model="mapDays" size="small" @change="loadOv">
                                    <el-radio-button :value="7">7日</el-radio-button>
                                    <el-radio-button :value="30">30日</el-radio-button>
                                    <el-radio-button :value="90">90日</el-radio-button>
                                </el-radio-group>
                            </div>
                            <WafChart v-if="ovMapOption" height="340px" :option="ovMapOption" />
                            <div v-else class="wf-empty">暂无可定位的访客（需要 locations 归属地数据）</div>
                            <div class="wf-map-legend"><span class="swatch" /> 访客数</div>
                        </section>

                        <div class="wf-stack">
                            <section class="wf-panel">
                                <h3 class="wf-title">实时请求数（1分钟）</h3>
                                <div class="wf-live">{{ ov.realtime?.req || 0 }}</div>
                            </section>
                            <section class="wf-panel">
                                <h3 class="wf-title">实时流量（1分钟）</h3>
                                <div class="wf-live">{{ fmtSize(ov.realtime?.flow || 0) }}</div>
                            </section>
                        </div>
                    </div>

                    <section class="wf-panel" style="margin-top: 12px">
                        <h3 class="wf-title">
                            访客趋势
                            <span class="wf-extra">
                                <el-radio-group v-model="visitorTrendDays" size="small" @change="loadVisitorTrend">
                                    <el-radio-button :value="1">今天</el-radio-button>
                                    <el-radio-button :value="7">近7天</el-radio-button>
                                    <el-radio-button :value="30">近30天</el-radio-button>
                                </el-radio-group>
                            </span>
                        </h3>
                        <WafChart v-if="visitorTrendOption" height="220px" :option="visitorTrendOption" />
                        <div v-else class="wf-empty">暂无趋势数据（site_stat 由 1pwaf 定时落库）</div>
                    </section>

                    <section class="wf-panel" style="margin-top: 12px">
                        <h3 class="wf-title">今日 24 小时分布</h3>
                        <WafChart v-if="ovHourOption" height="180px" :option="ovHourOption" />
                        <div v-else class="wf-empty">今日暂无数据</div>
                    </section>
                </div>
            </el-tab-pane>

            <!-- ================= 访问统计 ================= -->
            <el-tab-pane label="访问统计" name="traffic">
                <el-radio-group v-model="trafficDays" size="small" class="mb" @change="loadDims">
                    <el-radio-button :value="7">近 7 天</el-radio-button>
                    <el-radio-button :value="30">近 30 天</el-radio-button>
                    <el-radio-button :value="90">近 90 天</el-radio-button>
                </el-radio-group>
                <el-row :gutter="12">
                    <el-col :span="12">
                        <el-card shadow="never" class="mb">
                            <template #header><span class="title">状态码分布</span></template>
                            <WafChart v-if="dimPie(dims.status).length" height="260px" :option="pieOf('状态码', dimPie(dims.status))" />
                            <el-empty v-else :image-size="60" description="暂无数据" />
                        </el-card>
                    </el-col>
                    <el-col :span="12">
                        <el-card shadow="never" class="mb">
                            <template #header><span class="title">操作系统</span></template>
                            <WafChart v-if="dimPie(dims.os).length" height="260px" :option="pieOf('操作系统', dimPie(dims.os))" />
                            <el-empty v-else :image-size="60" description="暂无数据" />
                        </el-card>
                    </el-col>
                    <el-col :span="12">
                        <el-card shadow="never" class="mb">
                            <template #header><span class="title">浏览器</span></template>
                            <WafChart v-if="dimPie(dims.browser).length" height="260px" :option="pieOf('浏览器', dimPie(dims.browser))" />
                            <el-empty v-else :image-size="60" description="暂无数据" />
                        </el-card>
                    </el-col>
                    <el-col :span="12">
                        <el-card shadow="never" class="mb">
                            <template #header><span class="title">设备类型</span></template>
                            <WafChart v-if="dimPie(dims.device).length" height="260px" :option="pieOf('设备类型', dimPie(dims.device))" />
                            <el-empty v-else :image-size="60" description="暂无数据" />
                        </el-card>
                    </el-col>
                </el-row>
                <el-row :gutter="12">
                    <el-col :span="12" v-for="t in dimTables" :key="t.key">
                        <el-card shadow="never" class="mb">
                            <template #header><span class="title">{{ t.label }}</span></template>
                            <el-table :data="(dims as any)[t.key] || []" size="small" max-height="280">
                                <el-table-column type="index" label="#" width="50" />
                                <el-table-column prop="name" label="名称" show-overflow-tooltip />
                                <el-table-column prop="count" label="次数" width="110" sortable />
                            </el-table>
                        </el-card>
                    </el-col>
                </el-row>
            </el-tab-pane>

            <!-- ================= 趋势统计 ================= -->
            <el-tab-pane label="趋势统计" name="trend">
                <div class="mb" style="display: flex; gap: 12px; align-items: center">
                    <el-radio-group v-model="trendGran" size="small" @change="loadTrend">
                        <el-radio-button value="day">按天</el-radio-button>
                        <el-radio-button value="hour">按小时</el-radio-button>
                    </el-radio-group>
                    <el-radio-group v-model="trendDays" size="small" @change="loadTrend">
                        <el-radio-button :value="7">近 7 天</el-radio-button>
                        <el-radio-button :value="30">近 30 天</el-radio-button>
                        <el-radio-button :value="90">近 90 天</el-radio-button>
                    </el-radio-group>
                </div>
                <el-card shadow="never" class="mb">
                    <template #header><span class="title">请求 / PV / UV / 独立 IP</span></template>
                    <WafChart v-if="trendOption" height="300px" :option="trendOption" />
                    <el-empty v-else :image-size="60" description="暂无趋势数据（site_stat 由 1pwaf 定时落库）" />
                </el-card>
                <el-card shadow="never" class="mb">
                    <template #header><span class="title">4xx / 5xx / 爬虫</span></template>
                    <WafChart v-if="trendErrOption" height="260px" :option="trendErrOption" />
                    <el-empty v-else :image-size="60" description="暂无数据" />
                </el-card>
            </el-tab-pane>

            <!-- ================= 请求日志 ================= -->
            <el-tab-pane label="请求日志" name="logs">
                <el-card shadow="never" class="mb">
                    <div class="filter-bar">
                        <el-input v-model="logFilter.ip" placeholder="来源 IP" size="small" clearable style="width: 160px" @keyup.enter="loadLogs(1)" />
                        <el-input v-model="logFilter.uri" placeholder="URI 包含" size="small" clearable style="width: 180px" @keyup.enter="loadLogs(1)" />
                        <el-select v-model="logFilter.method" placeholder="方法" size="small" clearable style="width: 110px">
                            <el-option v-for="m in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']" :key="m" :value="m" :label="m" />
                        </el-select>
                        <el-input v-model="logFilter.status" placeholder="状态码" size="small" clearable style="width: 100px" @keyup.enter="loadLogs(1)" />
                        <el-button size="small" type="primary" @click="loadLogs(1)">查询</el-button>
                        <el-button size="small" @click="resetLogFilter">重置</el-button>
                        <span class="filter-total">共 {{ logTotal }} 条</span>
                    </div>
                    <el-table :data="logs" size="small" v-loading="logLoading" max-height="560">
                        <el-table-column prop="localtime" label="时间" width="170" />
                        <el-table-column prop="ip" label="来源 IP" width="140" />
                        <el-table-column prop="method" label="方法" width="80" />
                        <el-table-column prop="uri" label="URI" min-width="200" show-overflow-tooltip />
                        <el-table-column prop="status" label="状态码" width="90">
                            <template #default="{ row }">
                                <el-tag size="small" :type="row.status >= 500 ? 'danger' : row.status >= 400 ? 'warning' : 'success'">
                                    {{ row.status || '-' }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column prop="request_time" label="耗时(ms)" width="95" />
                        <el-table-column label="流量" width="130">
                            <template #default="{ row }">{{ fmtSize((row.send_bytes || 0) + (row.recv_bytes || 0)) }}</template>
                        </el-table-column>
                        <el-table-column prop="os" label="系统" width="110" show-overflow-tooltip />
                        <el-table-column prop="browser" label="浏览器" width="120" show-overflow-tooltip />
                        <el-table-column prop="spider" label="爬虫" width="110" show-overflow-tooltip />
                    </el-table>
                    <div class="pager">
                        <el-pagination
                            v-model:current-page="logPage"
                            :page-size="logSize"
                            :total="logTotal"
                            layout="prev, pager, next, total"
                            @current-change="loadLogs()" />
                    </div>
                </el-card>
            </el-tab-pane>

            <!-- ================= 网站列表 ================= -->
            <el-tab-pane label="网站列表" name="sites">
                <el-card shadow="never" class="mb">
                    <el-table :data="sites" size="small">
                        <el-table-column prop="key" label="站点" min-width="220" show-overflow-tooltip />
                        <el-table-column label="监控状态" width="140">
                            <template #default="{ row }">
                                <el-tag size="small" :type="row.state === 'on' ? 'success' : 'info'">
                                    {{ row.state === 'on' ? '已开启' : '未开启' }}
                                </el-tag>
                                <span class="dim" v-if="row.state_from === 'global'">（继承全局）</span>
                            </template>
                        </el-table-column>
                        <el-table-column prop="requests" label="已记录请求" width="130" sortable />
                        <el-table-column prop="last_time" label="最近请求" width="180" />
                        <el-table-column label="操作" width="160">
                            <template #default="{ row }">
                                <el-button size="small" link type="primary" @click="switchSite(row.key)">查看</el-button>
                                <el-button size="small" link :type="row.state === 'on' ? 'danger' : 'success'" @click="toggleSite(row)">
                                    {{ row.state === 'on' ? '关闭' : '开启' }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </el-card>
            </el-tab-pane>

            <!-- ================= 设置 ================= -->
            <el-tab-pane label="设置" name="setting">
                <el-card shadow="never" class="mb">
                    <template #header>
                        <div class="card-header">
                            <span class="title">监控设置（{{ cfgTarget }}）</span>
                            <el-radio-group v-model="cfgScope" size="small" @change="loadCfg">
                                <el-radio-button value="site">当前站点</el-radio-button>
                                <el-radio-button value="global">全局默认</el-radio-button>
                            </el-radio-group>
                        </div>
                    </template>
                    <el-form label-width="140px" size="small">
                        <el-form-item label="监控开关">
                            <el-switch v-model="cfg.state" active-value="on" inactive-value="off" />
                        </el-form-item>
                        <el-form-item label="排除的扩展名">
                            <el-select v-model="cfg.exclude.extensions" multiple filterable allow-create default-first-option style="width: 100%" placeholder="输入后回车添加，如 png、css" />
                        </el-form-item>
                        <el-form-item label="排除的状态码">
                            <el-select v-model="cfg.exclude.status" multiple filterable allow-create default-first-option style="width: 100%" placeholder="如 404" />
                        </el-form-item>
                        <el-form-item label="排除的 URI">
                            <el-input v-model="uriText" type="textarea" :rows="3" placeholder="每行一个，如 /favicon.ico" />
                        </el-form-item>
                        <el-form-item label="排除的 User-Agent">
                            <el-input v-model="uaText" type="textarea" :rows="3" placeholder="每行一个，支持包含匹配" />
                        </el-form-item>
                        <el-form-item label="排除的 IP">
                            <el-input v-model="ipText" type="textarea" :rows="3" placeholder="每行一个，支持 CIDR" />
                        </el-form-item>
                        <el-form-item label="日志保留天数">
                            <el-input-number v-model="cfg.log.maxDay" :min="1" :max="3650" />
                        </el-form-item>
                        <el-form-item label="单库大小上限(MB)">
                            <el-input-number v-model="cfg.log.maxSize" :min="1" :max="10240" />
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" size="small" @click="saveCfg">保存并生效</el-button>
                        </el-form-item>
                    </el-form>
                </el-card>
            </el-tab-pane>
        </el-tabs>
    </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import WafChart from './echart.vue';
import echarts from '@/utils/echarts';
import {
    getWafMonSites,
    getWafMonOverview,
    getWafMonTrend,
    getWafMonDims,
    getWafMonLogs,
    getWafMonConfig,
    getWafMonRealtime,
    saveWafMonConfig,
    saveWafMonState,
} from '@/api/modules/waf-log';

const loading = ref(false);
const tab = ref('overview');
const site = ref('');
const sites = ref<any[]>([]);
const siteState = ref('off');
const globalState = ref('off');
const ov = ref<any>({});
const dims = ref<any>({});
const logs = ref<any[]>([]);
const logTotal = ref(0);
const logPage = ref(1);
const logSize = ref(20);
const logLoading = ref(false);
const logFilter = ref<any>({ ip: '', uri: '', method: '', status: '' });
const trendRows = ref<any[]>([]);
const trendGran = ref<'day' | 'hour'>('day');
const trendDays = ref(30);
const trafficDays = ref(30);
const mapDays = ref(30);
const cfg = ref<any>({ state: 'off', exclude: { extensions: [], status: [], uri: [], ua: [], ip: [] }, log: { maxDay: 180, maxSize: 100 } });
const cfgScope = ref<'site' | 'global'>('site');
const cfgFrom = ref('');
const monitorEffective = computed(() => globalState.value === 'on' && siteState.value === 'on');
const monitorHint = computed(() =>
    globalState.value !== 'on' ? '全局开关未开启，不会产生数据' : siteState.value !== 'on' ? '当前站点未开启' : '',
);
let liveTimer: any = null;

const cfgTarget = computed(() => (cfgScope.value === 'global' ? '全局默认' : site.value));
const uriText = computed({
    get: () => (cfg.value.exclude?.uri || []).join('\n'),
    set: (v: string) => (cfg.value.exclude.uri = v.split('\n').map((x: string) => x.trim()).filter(Boolean)),
});
const uaText = computed({
    get: () => (cfg.value.exclude?.ua || []).join('\n'),
    set: (v: string) => (cfg.value.exclude.ua = v.split('\n').map((x: string) => x.trim()).filter(Boolean)),
});
const ipText = computed({
    get: () => (cfg.value.exclude?.ip || []).join('\n'),
    set: (v: string) => (cfg.value.exclude.ip = v.split('\n').map((x: string) => x.trim()).filter(Boolean)),
});

const num = (v: any) => Number(v || 0);
const fmtSize = (n: number) => {
    n = num(n);
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
};
const unwrap = (res: any) => res?.data ?? res;

const metricCards = computed(() => {
    const s = ov.value.sum || {};
    return [
        { key: 'pv', label: '今日 PV', value: num(s.pv).toLocaleString() },
        { key: 'uv', label: '今日 UV', value: num(s.uv).toLocaleString() },
        { key: 'ip', label: '今日独立 IP', value: num(s.ip).toLocaleString() },
        { key: 'req', label: '今日请求数', value: num(s.req).toLocaleString() },
        { key: 'flow', label: '今日流量', value: fmtSize(num(s.flow)) },
        { key: 'spider', label: '今日爬虫', value: num(s.spider).toLocaleString() },
        { key: 'count4xx', label: '今日 4xx', value: num(s.count4xx).toLocaleString() },
        { key: 'count5xx', label: '今日 5xx', value: num(s.count5xx).toLocaleString() },
    ];
});

// ---------- 概览图表 ----------
let worldRegistered = false;
let chinaRegistered = false;
const mapMode = ref<'world' | 'china'>('china');
const mapMetric = ref<'source' | 'count'>('count');
const visitorTrendDays = ref(7);
const mapTick = ref(0);
const PROV_EN: Record<string, string> = {
    北京: 'Beijing', 天津: 'Tianjin', 河北: 'Hebei', 山西: 'Shanxi', 内蒙古: 'Inner Mongolia',
    辽宁: 'Liaoning', 吉林: 'Jilin', 黑龙江: 'Heilongjiang', 上海: 'Shanghai', 江苏: 'Jiangsu',
    浙江: 'Zhejiang', 安徽: 'Anhui', 福建: 'Fujian', 江西: 'Jiangxi', 山东: 'Shandong',
    河南: 'Henan', 湖北: 'Hubei', 湖南: 'Hunan', 广东: 'Guangdong', 广西: 'Guangxi',
    海南: 'Hainan', 重庆: 'Chongqing', 四川: 'Sichuan', 贵州: 'Guizhou', 云南: 'Yunnan',
    西藏: 'Xizang', 陕西: 'Shaanxi', 甘肃: 'Gansu', 青海: 'Qinghai', 宁夏: 'Ningxia',
    新疆: 'Xinjiang', 香港: 'Hong Kong', 澳门: 'Macao', 台湾: 'Taiwan',
};
const ensureWorld = async () => {
    if (!worldRegistered) {
        const mod: any = await import('./maps/world.json');
        echarts.registerMap('wafWorld', (mod.default || mod) as any);
        worldRegistered = true;
    }
    if (!chinaRegistered) {
        const mod: any = await import('./maps/china.json');
        echarts.registerMap('wafChina', (mod.default || mod) as any);
        chinaRegistered = true;
    }
    mapTick.value++;
};

const ovHourOption = computed(() => {
    const hs = ov.value.hours || [];
    if (!hs.length) return null;
    const hours = hs.map((h: any) => h.hour + ':00');
    return {
        tooltip: { trigger: 'axis' },
        legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
        grid: { left: 50, right: 20, top: 20, bottom: 44 },
        xAxis: { type: 'category', data: hours, axisLabel: { fontSize: 10 } },
        yAxis: { type: 'value', minInterval: 1 },
        series: [
            { name: 'PV', type: 'line', smooth: true, showSymbol: false, data: hs.map((h: any) => num(h.pv)), areaStyle: { opacity: 0.15 } },
            { name: 'UV', type: 'line', smooth: true, showSymbol: false, data: hs.map((h: any) => num(h.uv)) },
            { name: '爬虫', type: 'line', smooth: true, showSymbol: false, data: hs.map((h: any) => num(h.spider)) },
        ],
    };
});

const ovMapOption = computed(() => {
    void mapTick.value;
    const isChina = mapMode.value === 'china';
    if (isChina ? !chinaRegistered : !worldRegistered) return null;
    const mapName = isChina ? 'wafChina' : 'wafWorld';
    const countries = ov.value.countries || [];
    const provinces = ov.value.provinces || [];

    if (mapMetric.value === 'count') {
        const data = isChina
            ? provinces.map((p: any) => ({ name: PROV_EN[p.name] || p.name, value: num(p.count) }))
            : countries.map((c: any) => ({ name: c.name_en || c.name, value: num(c.count) }));
        const max = Math.max(...data.map((d: any) => d.value), 1);
        return {
            tooltip: { trigger: 'item', formatter: (p: any) => `${p.name}：${p.value || 0} 次` },
            visualMap: {
                min: 0, max, orient: 'horizontal', seriesIndex: 0, left: 18, bottom: 8, calculable: false,
                text: ['高', '低'], textStyle: { fontSize: 10, color: '#909399' },
                inRange: { color: ['#e8f0ff', '#2b6cff'] },
            },
            series: [{
                type: 'map', map: mapName, roam: true,
                aspectScale: 0.85, preserveAspect: true,
                preserveAspectAlign: 'center', preserveAspectVerticalAlign: 'middle', zoom: 1,
                left: 10, right: 10, top: 10, bottom: 34,
                itemStyle: { areaColor: '#f5f7fa', borderColor: '#dfe4ec', borderWidth: 0.6 },
                emphasis: { label: { show: false }, itemStyle: { areaColor: '#dbe7ff' } },
                label: { show: false }, data,
            }],
        };
    }

    const list = isChina
        ? provinces.filter((p: any) => p.lat || p.lon).map((p: any) => ({ lon: p.lon, lat: p.lat, count: p.count, name: p.name }))
        : countries.filter((c: any) => c.lon || c.lat);
    if (!list.length) return null;
    const max = Math.max(...list.map((c: any) => num(c.count)), 1);
    return {
        tooltip: { trigger: 'item', formatter: (p: any) => `${p.data[3]}：${p.data[2]} 次` },
        geo: {
            map: mapName, roam: true,
            aspectScale: 0.85, preserveAspect: true,
            preserveAspectAlign: 'center', preserveAspectVerticalAlign: 'middle', zoom: 1,
            left: 10, right: 10, top: 10, bottom: 34,
            itemStyle: { areaColor: '#f5f7fa', borderColor: '#dfe4ec', borderWidth: 0.6 },
            emphasis: { itemStyle: { areaColor: '#dbe7ff' }, label: { show: false } },
            label: { show: false },
        },
        series: [{
            type: 'effectScatter', coordinateSystem: 'geo',
            data: list.map((c: any) => [num(c.lon), num(c.lat), num(c.count), c.name]),
            symbolSize: (v: any) => 5 + Math.sqrt(v[2] / max) * 16,
            rippleEffect: { brushType: 'stroke', scale: 2.6 },
            itemStyle: { color: '#409eff', shadowBlur: 8, shadowColor: 'rgba(64,158,255,0.45)' },
            label: { show: true, formatter: (p: any) => p.data[3], position: 'right', fontSize: 11, color: '#909399' },
        }],
    };
});

const visitorTrendOption = computed(() => {
    const rows = trendRows.value;
    if (!rows.length) return null;
    const x = rows.map((r: any) => (trendGran.value === 'hour' ? (r.day + ' ' + r.hour + ':00').slice(5) : r.day.slice(5)));
    return {
        tooltip: { trigger: 'axis' },
        legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
        grid: { left: 50, right: 20, top: 20, bottom: 44 },
        xAxis: { type: 'category', data: x, axisLabel: { fontSize: 10, interval: Math.max(0, Math.floor(x.length / 8) - 1) } },
        yAxis: { type: 'value', minInterval: 1 },
        series: [
            { name: 'PV', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.pv)), areaStyle: { opacity: 0.12 } },
            { name: 'UV', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.uv)) },
            { name: '独立 IP', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.ip)) },
        ],
    };
});

const loadVisitorTrend = async () => {
    trendDays.value = visitorTrendDays.value;
    trendGran.value = visitorTrendDays.value === 1 ? 'hour' : 'day';
    await loadTrend();
};

// ---------- 访问统计 ----------
const dimPie = (list: any[]) => (list || []).map((x) => ({ name: x.name, value: num(x.count) }));
const pieOf = (name: string, data: any[]) => ({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { type: 'scroll', bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
    series: [
        {
            name,
            type: 'pie',
            radius: ['38%', '66%'],
            center: ['50%', '44%'],
            data,
            label: { fontSize: 11, formatter: '{b} {d}%' },
            itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 1 },
        },
    ],
});
const dimTables = [
    { key: 'ip', label: '来源 IP TOP' },
    { key: 'uri', label: '请求 URI TOP' },
    { key: 'referer', label: '来源页 TOP' },
    { key: 'spider', label: '爬虫 TOP' },
    { key: 'method', label: '请求方法' },
    { key: 'contents', label: 'Content-Type TOP' },
];

// ---------- 趋势 ----------
const trendOption = computed(() => {
    const rows = trendRows.value;
    if (!rows.length) return null;
    const x = rows.map((r: any) => (trendGran.value === 'hour' ? (r.day + ' ' + r.hour + ':00').slice(5) : r.day.slice(5)));
    return {
        tooltip: { trigger: 'axis' },
        legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
        grid: { left: 55, right: 20, top: 20, bottom: 44 },
        xAxis: { type: 'category', data: x, axisLabel: { fontSize: 10 } },
        yAxis: { type: 'value', minInterval: 1 },
        series: [
            { name: 'PV', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.pv)), areaStyle: { opacity: 0.12 } },
            { name: 'UV', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.uv)) },
            { name: '独立 IP', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.ip)) },
            { name: '请求数', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.req)) },
        ],
    };
});
const trendErrOption = computed(() => {
    const rows = trendRows.value;
    if (!rows.length) return null;
    const x = rows.map((r: any) => (trendGran.value === 'hour' ? (r.day + ' ' + r.hour + ':00').slice(5) : r.day.slice(5)));
    return {
        tooltip: { trigger: 'axis' },
        legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
        grid: { left: 55, right: 20, top: 20, bottom: 44 },
        xAxis: { type: 'category', data: x, axisLabel: { fontSize: 10 } },
        yAxis: { type: 'value', minInterval: 1 },
        series: [
            { name: '4xx', type: 'line', step: 'middle', data: rows.map((r: any) => num(r.count4xx)), itemStyle: { color: '#e6a23c' } },
            { name: '5xx', type: 'line', step: 'middle', data: rows.map((r: any) => num(r.count5xx)), itemStyle: { color: '#f56c6c' } },
            { name: '爬虫', type: 'line', smooth: true, showSymbol: false, data: rows.map((r: any) => num(r.spider)), itemStyle: { color: '#909399' } },
        ],
    };
});

// ---------- 数据加载 ----------
const loadSites = async () => {
    const d = unwrap(await getWafMonSites());
    sites.value = d.sites || [];
    if (!site.value && sites.value.length) site.value = sites.value[0].key;
    globalState.value = d.global?.state === 'on' ? 'on' : 'off';
    const cur = sites.value.find((s) => s.key === site.value);
    if (cur) siteState.value = cur.state === 'on' ? 'on' : 'off';
};
const loadOv = async () => {
    if (!site.value) return;
    ov.value = unwrap(await getWafMonOverview({ site: site.value, days: mapDays.value }));
    await ensureWorld();
};
const loadDims = async () => {
    if (!site.value) return;
    const d = unwrap(await getWafMonDims({ site: site.value, days: trafficDays.value }));
    dims.value = d.dims || {};
};
const loadTrend = async () => {
    if (!site.value) return;
    const d = unwrap(await getWafMonTrend({ site: site.value, days: trendDays.value, gran: trendGran.value }));
    trendRows.value = d.rows || [];
};
const loadLogs = async (page?: number) => {
    if (!site.value) return;
    if (page) logPage.value = page;
    logLoading.value = true;
    try {
        const d = unwrap(await getWafMonLogs({ site: site.value, page: logPage.value, size: logSize.value, ...logFilter.value }));
        logs.value = d.rows || [];
        logTotal.value = num(d.total);
    } finally {
        logLoading.value = false;
    }
};
const resetLogFilter = () => {
    logFilter.value = { ip: '', uri: '', method: '', status: '' };
    loadLogs(1);
};
const loadCfg = async () => {
    const d = unwrap(await getWafMonConfig({ site: cfgScope.value === 'global' ? '' : site.value }));
    cfgFrom.value = d.from || '';
    if (d.config) cfg.value = { state: 'off', exclude: { extensions: [], status: [], uri: [], ua: [], ip: [] }, log: { maxDay: 180, maxSize: 100 }, ...d.config };
};
const saveCfg = async () => {
    cfg.value.exclude.status = (cfg.value.exclude.status || []).map((x: any) => Number(x) || 0).filter((x: number) => x > 0);
    await saveWafMonConfig({ site: cfgScope.value === 'global' ? '' : site.value, config: cfg.value });
    await loadSites();
};
const toggleState = async (v: any) => {
    await saveWafMonState({ site: site.value, state: v === 'on' ? 'on' : 'off' });
    await loadSites();
};
const toggleGlobal = async (v: any) => {
    await saveWafMonState({ site: '', state: v === 'on' ? 'on' : 'off' });
    await loadSites();
};
const toggleSite = async (row: any) => {
    await saveWafMonState({ site: row.key, state: row.state === 'on' ? 'off' : 'on' });
    await loadSites();
};
const switchSite = (key: string) => {
    site.value = key;
    loadAll();
};

const loadAll = async () => {
    loading.value = true;
    try {
        await loadSites();
        await Promise.all([loadOv(), loadDims(), loadTrend(), loadLogs(1), loadCfg()]);
    } finally {
        loading.value = false;
    }
};

onMounted(async () => {
    await loadAll();
    liveTimer = setInterval(async () => {
        if (tab.value !== 'overview' || !site.value) return;
        try {
            const d = unwrap(await getWafMonRealtime({ site: site.value, window: 60 }));
            ov.value.realtime = { req: num(d.req), flow: num(d.flow), window: 60 };
        } catch {
            /* 实时轮询失败不影响页面 */
        }
    }, 5000);
});
onBeforeUnmount(() => {
    if (liveTimer) clearInterval(liveTimer);
});
</script>

<style src="./flat.css"></style>
<style lang="scss" scoped>
.waf-monitor {
    .wf-flat .wf-seg :deep(.el-radio-button__inner) {
        padding: 5px 12px;
        font-size: 12px;
    }
    .mb {
        margin-bottom: 12px;
    }
    .top-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        .left {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .page-title {
            font-size: 16px;
            font-weight: 600;
        }
    }
    .sw-label {
        font-size: 12px;
        color: var(--el-text-color-secondary);
        margin-left: 10px;
        margin-right: 4px;
    }
    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        .title {
            font-size: 14px;
            font-weight: 600;
        }
    }
    .title {
        font-size: 14px;
        font-weight: 600;
    }
    .metric {
        .metric-label {
            font-size: 12px;
            color: var(--el-text-color-secondary);
        }
        .metric-value {
            font-size: 22px;
            font-weight: 600;
            margin-top: 4px;
        }
    }
    .live-row {
        display: flex;
        justify-content: space-around;
        padding: 12px 0;
        .live-item {
            text-align: center;
            .live-num {
                font-size: 26px;
                font-weight: 600;
            }
            .live-label {
                font-size: 12px;
                color: var(--el-text-color-secondary);
                margin-top: 4px;
            }
        }
    }
    .live-tip {
        font-size: 12px;
        color: var(--el-text-color-secondary);
        text-align: center;
    }
    .filter-bar {
        display: flex;
        gap: 8px;
        align-items: center;
        margin-bottom: 10px;
        .filter-total {
            margin-left: auto;
            color: var(--el-text-color-secondary);
            font-size: 12px;
        }
    }
    .pager {
        display: flex;
        justify-content: flex-end;
        margin-top: 10px;
    }
    .dim {
        font-size: 12px;
        color: var(--el-text-color-secondary);
    }
}
</style>
