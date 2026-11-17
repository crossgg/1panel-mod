<template>
    <div class="waf-overview wf-flat">
        <el-alert
            v-if="!data.ok"
            :title="data.hint || '未检测到 1pwaf 数据目录'"
            type="warning"
            show-icon
            :closable="false"
            class="wf-panel"
            style="margin-bottom: 12px"
        />

        <div class="wf-grid">
            <div class="wf-stack">
                <section class="wf-panel">
                    <h3 class="wf-title">今日状态</h3>
                    <div class="wf-kpis">
                        <div class="wf-kpi" v-for="c in statusCells" :key="c.k">
                            <div class="k">{{ c.k }}</div>
                            <div class="v">{{ c.v }}</div>
                        </div>
                    </div>
                </section>

                <section class="wf-panel">
                    <h3 class="wf-title">
                        拦截地图（{{ mapDays }}日）
                        <span class="wf-extra">共 {{ mapData.total || 0 }} 次 · 覆盖 {{ mapData.countries?.length || 0 }} 个国家/地区</span>
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
                        <el-radio-group v-model="mapDays" size="small" @change="loadMap">
                            <el-radio-button :value="7">7日</el-radio-button>
                            <el-radio-button :value="30">30日</el-radio-button>
                            <el-radio-button :value="90">90日</el-radio-button>
                        </el-radio-group>
                    </div>
                    <WafChart v-if="mapOption" height="360px" :option="mapOption" />
                    <div v-else class="wf-empty">
                        {{ mapData.total ? '全部来源都是内网地址，暂无地理位置' : '所选时间范围内没有拦截记录' }}
                    </div>
                    <div class="wf-map-legend"><span class="swatch" /> 拦截数</div>
                    <div v-if="topCountryText" class="wf-foot">{{ topCountryText }}</div>
                </section>
            </div>

            <div class="wf-stack">
                <section class="wf-panel">
                    <h3 class="wf-title">请求趋势（7日）</h3>
                    <WafChart v-if="miniReqOption" height="130px" :option="miniReqOption" />
                    <div v-else class="wf-empty">暂无数据</div>
                </section>
                <section class="wf-panel">
                    <h3 class="wf-title">拦截趋势（7日）</h3>
                    <WafChart v-if="miniBlockOption" height="130px" :option="miniBlockOption" />
                    <div v-else class="wf-empty">暂无数据</div>
                </section>
            </div>
        </div>

        <div class="wf-grid-half" style="margin-top: 12px">
            <section class="wf-panel">
                <h3 class="wf-title">
                    请求与拦截趋势（近 {{ days }} 天）
                    <span class="wf-extra">
                        <el-radio-group v-model="days" size="small" @change="load">
                            <el-radio-button :value="7">7 天</el-radio-button>
                            <el-radio-button :value="30">30 天</el-radio-button>
                            <el-radio-button :value="90">90 天</el-radio-button>
                        </el-radio-group>
                    </span>
                </h3>
                <WafChart v-if="trendOption" height="250px" :option="trendOption" />
                <div v-else class="wf-empty">暂无趋势数据</div>
            </section>
            <section class="wf-panel">
                <h3 class="wf-title">攻击类型占比</h3>
                <WafChart v-if="pieOption" height="250px" :option="pieOption" />
                <div v-else class="wf-empty">今日暂无攻击</div>
            </section>
        </div>

        <section class="wf-panel" style="margin-top: 12px">
            <h3 class="wf-title">今日 24 小时攻击分布<span class="wf-extra">共 {{ todayAttack }} 次</span></h3>
            <WafChart v-if="hourOption" height="180px" :option="hourOption" />
            <div v-else class="wf-empty">今日暂无攻击</div>
        </section>

        <div class="wf-grid-boards" style="margin-top: 12px">
            <section class="wf-panel" v-for="board in boards" :key="board.key">
                <h3 class="wf-title">{{ board.title }}<span class="wf-extra">{{ board.list.length }} 项</span></h3>
                <div v-if="!board.list.length" class="wf-empty">暂无数据</div>
                <div v-for="(it, i) in board.list" :key="it.value + i" class="wf-board-row">
                    <span class="rank" :class="{ top3: i < 3 }">{{ i + 1 }}</span>
                    <span class="val" :title="it.value">{{ it.extra ? it.extra + ' · ' : '' }}{{ it.value }}</span>
                    <div class="bar-wrap">
                        <div class="bar" :style="{ width: barWidth(board.list, it.count), background: board.color }" />
                    </div>
                    <span class="cnt">{{ it.count }}</span>
                </div>
            </section>
        </div>

        <div class="wf-foot">
            <span>数据实例：{{ data.instances || 0 }} 个 · 拦截库累计 {{ data.total_logs || 0 }} 条 · 站点 {{ data.site_count || 0 }} 个</span>
            <el-button link type="primary" @click="load">刷新</el-button>
        </div>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import WafChart from './echart.vue';
import echarts from '@/utils/echarts';
import { getWafAttackMap, getWafOverview } from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const loading = ref(false);
const days = ref(30);
const data = ref<any>({
    ok: false,
    today: {},
    yesterday: {},
    trend: [],
    hourly: [],
    top_ips: [],
    top_uris: [],
    top_rules: [],
    top_rule_types: [],
    top_locations: [],
    top_actions: [],
    total_logs: 0,
    site_count: 0,
    instances: 0,
});

const num = (v: any) => (typeof v === 'number' ? v : Number(v) || 0);

const todayAttack = computed(() => num(data.value.today?.attack_count));
const todayReq = computed(() => num(data.value.today?.req_count));

const delta = (cur: number, prev: number) => {
    if (prev <= 0) return cur > 0 ? '昨日无数据' : '持平';
    const p = ((cur - prev) / prev) * 100;
    return `${p >= 0 ? '↑' : '↓'} ${Math.abs(p).toFixed(1)}% 环比`;
};

const cards = computed(() => {
    const t = data.value.today || {};
    const y = data.value.yesterday || {};
    const rate = num(t.block_rate);
    return [
        {
            key: 'req',
            label: '今日请求',
            value: num(t.req_count),
            hint: '实时',
            tag: 'primary',
            color: '#409eff',
            foot: delta(num(t.req_count), num(y.req_count)),
        },
        {
            key: 'attack',
            label: '今日拦截',
            value: num(t.attack_count),
            hint: '攻击',
            tag: 'danger',
            color: '#f56c6c',
            foot: delta(num(t.attack_count), num(y.attack_count)),
        },
        {
            key: 'rate',
            label: '拦截率',
            value: `${rate}%`,
            hint: '危险占比',
            tag: 'warning',
            color: rate >= 50 ? '#e6a23c' : '#67c23a',
            foot: `4xx ${num(t.count4xx)} 次`,
        },
        {
            key: 'total',
            label: '累计拦截记录',
            value: num(data.value.total_logs),
            hint: '全量',
            tag: 'info',
            color: '#909399',
            foot: `覆盖 ${data.value.instances || 0} 个 WAF 实例`,
        },
    ];
});

const trendOption = computed(() => {
    const list = data.value.trend || [];
    if (!list.length) return null;
    return {
        tooltip: { trigger: 'axis' },
        legend: { data: ['请求数', '拦截数'], right: 10, top: 0 },
        grid: { left: 46, right: 20, top: 36, bottom: 28 },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: list.map((x: any) => String(x.day).slice(5)),
            axisLabel: { fontSize: 11 },
        },
        yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 11 } },
        series: [
            {
                name: '请求数',
                type: 'line',
                smooth: true,
                showSymbol: false,
                areaStyle: { opacity: 0.12 },
                itemStyle: { color: '#409eff' },
                data: list.map((x: any) => num(x.req_count)),
            },
            {
                name: '拦截数',
                type: 'line',
                smooth: true,
                showSymbol: false,
                areaStyle: { opacity: 0.12 },
                itemStyle: { color: '#f56c6c' },
                data: list.map((x: any) => num(x.attack_count)),
            },
        ],
    };
});

const pieOption = computed(() => {
    const list = data.value.top_rule_types || [];
    const items = list.filter((x: any) => x.count > 0);
    if (!items.length) return null;
    return {
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { bottom: 0, type: 'scroll', itemWidth: 10, itemHeight: 10, textStyle: { fontSize: 11 } },
        series: [
            {
                type: 'pie',
                radius: ['42%', '68%'],
                center: ['50%', '44%'],
                avoidLabelOverlap: true,
                label: { show: false },
                emphasis: { label: { show: true, fontSize: 12, fontWeight: 'bold' } },
                data: items.map((x: any) => ({ name: x.value, value: x.count })),
            },
        ],
    };
});

const hourOption = computed(() => {
    const list = data.value.hourly || [];
    if (!list.length) return null;
    return {
        tooltip: { trigger: 'axis', formatter: '{b} 时：{c} 次' },
        grid: { left: 40, right: 16, top: 20, bottom: 26 },
        xAxis: {
            type: 'category',
            data: list.map((x: any) => String(x.hour).padStart(2, '0')),
            axisLabel: { fontSize: 11, interval: 1 },
        },
        yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 11 } },
        series: [
            {
                type: 'line',
                smooth: true,
                symbol: 'circle',
                symbolSize: 5,
                areaStyle: { opacity: 0.25 },
                itemStyle: { color: '#e6a23c' },
                data: list.map((x: any) => num(x.count)),
            },
        ],
    };
});

const barWidth = (list: any[], count: number) => {
    const max = Math.max(...list.map((x: any) => num(x.count)), 1);
    return `${Math.max(3, Math.round((count / max) * 100))}%`;
};

const boards = computed(() => [
    { key: 'ip', title: '攻击来源 IP', list: (data.value.top_ips || []).slice(0, 10), color: '#f56c6c' },
    { key: 'uri', title: '被攻击 URL', list: (data.value.top_uris || []).slice(0, 10), color: '#e6a23c' },
    { key: 'rule', title: '命中规则', list: (data.value.top_rules || []).slice(0, 10), color: '#409eff' },
    { key: 'loc', title: '来源归属地', list: (data.value.top_locations || []).slice(0, 10), color: '#67c23a' },
]);

const load = async () => {
    loading.value = true;
    try {
        const res = await getWafOverview({ days: days.value, top: 10 });
        data.value = { ...data.value, ...unwrap(res) };
    } catch (e) {
        data.value = { ...data.value, ok: false, hint: '概览数据加载失败' };
    } finally {
        loading.value = false;
    }
};

// ---------------- 拦截地图 ----------------
const mapDays = ref(30);
const mapData = ref<any>({ total: 0, blocked: 0, countries: [], provinces: [], unknown: 0 });
const mapTick = ref(0);
let mapRegistered = false;
let chinaRegistered = false;
const mapMode = ref<'world' | 'china'>('china');
const mapMetric = ref<'source' | 'count'>('count');

// china.json 的 properties.name 是英文省名，后端 provinces 返回中文名
const PROV_EN: Record<string, string> = {
    北京: 'Beijing', 天津: 'Tianjin', 河北: 'Hebei', 山西: 'Shanxi', 内蒙古: 'Inner Mongolia',
    辽宁: 'Liaoning', 吉林: 'Jilin', 黑龙江: 'Heilongjiang', 上海: 'Shanghai', 江苏: 'Jiangsu',
    浙江: 'Zhejiang', 安徽: 'Anhui', 福建: 'Fujian', 江西: 'Jiangxi', 山东: 'Shandong',
    河南: 'Henan', 湖北: 'Hubei', 湖南: 'Hunan', 广东: 'Guangdong', 广西: 'Guangxi',
    海南: 'Hainan', 重庆: 'Chongqing', 四川: 'Sichuan', 贵州: 'Guizhou', 云南: 'Yunnan',
    西藏: 'Xizang', 陕西: 'Shaanxi', 甘肃: 'Gansu', 青海: 'Qinghai', 宁夏: 'Ningxia',
    新疆: 'Xinjiang', 香港: 'Hong Kong', 澳门: 'Macao', 台湾: 'Taiwan',
};

const ensureMap = async () => {
    if (!mapRegistered) {
        const mod: any = await import('./maps/world.json');
        echarts.registerMap('wafWorld', (mod.default || mod) as any);
        mapRegistered = true;
    }
    if (!chinaRegistered) {
        const mod: any = await import('./maps/china.json');
        echarts.registerMap('wafChina', (mod.default || mod) as any);
        chinaRegistered = true;
    }
    mapTick.value++;
};

const loadMap = async () => {
    try {
        const d = unwrap(await getWafAttackMap({ days: mapDays.value }));
        mapData.value = d;
        await ensureMap();
        mapTick.value++;
    } catch {
        mapData.value = { total: 0, blocked: 0, countries: [], provinces: [], unknown: 0 };
    }
};

const mapOption = computed(() => {
    void mapTick.value;
    const isChina = mapMode.value === 'china';
    if (isChina ? !chinaRegistered : !mapRegistered) return null;

    const countries = (mapData.value.countries || []).filter((c: any) => !c.private);
    const provinces = mapData.value.provinces || [];
    const mapName = isChina ? 'wafChina' : 'wafWorld';
    const baseGeo: any = {
        map: mapName,
        roam: true,
        // ECharts 6.x：不显式写 preserveAspect:true 时，四边固定会非等比拉伸地图。
        // aspectScale 0.85 让中国地图接近官方截图的 ~1.5:1；bottom 留 34px 给水平 visualMap。
        aspectScale: 0.85,
        preserveAspect: true,
        preserveAspectAlign: 'center',
        preserveAspectVerticalAlign: 'middle',
        zoom: 1,
        left: 10, right: 10, top: 10, bottom: 34,
        itemStyle: { areaColor: '#f5f7fa', borderColor: '#dfe4ec', borderWidth: 0.6 },
        emphasis: { itemStyle: { areaColor: '#dbe7ff' }, label: { show: false } },
        label: { show: false },
    };

    // 数量模式： choropleth 填色 + visualMap 渐变（对齐官方截图）
    if (mapMetric.value === 'count') {
        const data = isChina
            ? provinces.map((p: any) => ({ name: PROV_EN[p.name] || p.name, value: num(p.count) }))
            : countries.map((c: any) => ({ name: c.name_en || c.name, value: num(c.count) }));
        const max = Math.max(...data.map((d: any) => d.value), 1);
        return {
            tooltip: { trigger: 'item', formatter: (p: any) => `${p.name}：${p.value || 0} 次` },
            visualMap: {
                min: 0,
                max,
                orient: 'horizontal',
                seriesIndex: 0,
                left: 18,
                bottom: 8,
                calculable: false,
                text: ['高', '低'],
                textStyle: { fontSize: 10, color: '#909399' },
                inRange: { color: ['#e8f0ff', '#2b6cff'] },
            },
            series: [
                {
                    type: 'map',
                    map: mapName,
                    roam: true,
                    aspectScale: 0.85,
                    preserveAspect: true,
                    preserveAspectAlign: 'center',
                    preserveAspectVerticalAlign: 'middle',
                    zoom: 1,
                    left: 10, right: 10, top: 10, bottom: 34,
                    itemStyle: { areaColor: '#f5f7fa', borderColor: '#dfe4ec', borderWidth: 0.6 },
                    emphasis: { label: { show: false }, itemStyle: { areaColor: '#dbe7ff' } },
                    label: { show: false },
                    data,
                },
            ],
        };
    }

    // 来源模式：涟漪散点
    const list = isChina
        ? provinces.filter((p: any) => p.lat || p.lon).map((p: any) => ({ lon: p.lon, lat: p.lat, count: p.count, name: p.name }))
        : countries.filter((c: any) => c.lat || c.lon);
    if (!list.length) return null;
    const max = Math.max(...list.map((c: any) => num(c.count)), 1);
    return {
        tooltip: { trigger: 'item', formatter: (p: any) => `${p.data[3]}：${p.data[2]} 次` },
        geo: baseGeo,
        series: [
            {
                type: 'effectScatter',
                coordinateSystem: 'geo',
                data: list.map((c: any) => [c.lon, c.lat, c.count, c.name]),
                symbolSize: (v: any) => 5 + Math.sqrt(v[2] / max) * 16,
                rippleEffect: { brushType: 'stroke', scale: 2.6 },
                itemStyle: { color: '#f56c6c', shadowBlur: 8, shadowColor: 'rgba(245,108,108,0.45)' },
                label: { show: true, formatter: (p: any) => p.data[3], position: 'right', fontSize: 11, color: '#909399' },
            },
        ],
    };
});

// 今日状态四宫格 + 右侧 7 日小卡
const statusCells = computed(() => {
    const t = data.value.today || {};
    return [
        { k: '请求', v: num(t.req_count).toLocaleString() },
        { k: '拦截', v: num(t.attack_count).toLocaleString() },
        { k: '4xx 数量', v: num(t.count4xx).toLocaleString() },
        { k: '5xx 数量', v: num(t.count5xx).toLocaleString() },
    ];
});
const miniTrend = computed(() => (data.value.trend || []).slice(-7));
const miniOption = (key: string, color: string) => {
    const list = miniTrend.value;
    if (!list.length) return null;
    return {
        grid: { left: 36, right: 10, top: 10, bottom: 20 },
        xAxis: { type: 'category', boundaryGap: false, data: list.map((x: any) => String(x.day).slice(5)), axisLabel: { fontSize: 10, interval: 1 } },
        yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 10 } },
        series: [
            {
                type: 'line',
                smooth: true,
                showSymbol: false,
                itemStyle: { color },
                areaStyle: { opacity: 0.12, color },
                data: list.map((x: any) => num(x[key])),
            },
        ],
    };
};
const miniReqOption = computed(() => miniOption('req_count', '#2b6cff'));
const miniBlockOption = computed(() => miniOption('attack_count', '#f56c6c'));

const topCountryText = computed(() => {
    const list = (mapData.value.countries || []).filter((c: any) => !c.private).slice(0, 5);
    if (!list.length) return '';
    return 'TOP 来源：' + list.map((c: any) => `${c.name} ${c.count}`).join(' · ');
});

onMounted(() => {
    load();
    loadMap();
});
</script>

<style src="./flat.css"></style>
<style lang="scss" scoped>
.wf-flat .wf-seg :deep(.el-radio-button__inner) {
    padding: 5px 12px;
    font-size: 12px;
}
</style>
