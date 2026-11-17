<template>
    <LayoutContent title="网站设置" :back-to="{ path: '/waf-log/site' }">
        <template #leftToolBar>
            <el-select
                v-model="curKey"
                filterable
                class="p-w-200 mr-2.5"
                style="width: 200px"
                @change="onSiteChange"
            >
                <template #prefix>网站</template>
                <el-option v-for="s in sites" :key="s.key" :label="s.key" :value="s.key" />
            </el-select>
            <el-button type="primary" :plain="tab !== '0'" @click="tab = '0'">频率限制</el-button>
            <el-button type="primary" :plain="tab !== '1'" @click="tab = '1'">默认规则</el-button>
            <el-button type="primary" :plain="tab !== '2'" @click="tab = '2'">自定义规则</el-button>
        </template>
        <template #main>
            <div v-loading="loading">
                <!-- 主开关 -->
                <div class="waf-main-switch">
                    <div class="waf-main-switch__header">
                        <div class="waf-main-switch__info">
                            <div class="waf-main-switch__title">
                                <span class="waf-main-switch__mark"></span>
                                <span>WAF 开关</span>
                                <el-tag :type="waf.state === 'on' ? 'success' : 'info'" effect="light">
                                    {{ waf.state === 'on' ? '已启用' : '已关闭' }}
                                </el-tag>
                                <el-tag v-if="waf.state === 'on' && waf.mode === 'observation'" type="warning" effect="light">
                                    观察模式
                                </el-tag>
                                <el-tag v-if="waf.state === 'on' && cfg.strict && cfg.strict.state === 'on'" effect="light">
                                    严格
                                </el-tag>
                            </div>
                            <span class="waf-main-switch__description">关闭之后此网站将失去防护</span>
                        </div>
                        <el-switch
                            :model-value="waf.state"
                            active-value="on"
                            inactive-value="off"
                            active-text="启动"
                            inactive-text="关闭"
                            inline-prompt
                            @change="toggleWaf"
                        />
                    </div>
                    <div class="waf-main-switch__controls">
                        <div class="waf-main-switch__control">
                            <span class="waf-main-switch__label">执行策略</span>
                            <el-radio-group
                                v-model="waf.mode"
                                class="compact-segment"
                                :disabled="waf.state !== 'on'"
                                @change="setMode"
                            >
                                <el-radio-button value="protection">保护模式</el-radio-button>
                                <el-radio-button value="observation">观察模式</el-radio-button>
                            </el-radio-group>
                            <el-alert
                                v-if="waf.mode === 'observation'"
                                type="warning"
                                :closable="false"
                                title="仅检测并记录日志，不会拦截请求"
                                class="inline-alert"
                            />
                        </div>
                        <div class="waf-main-switch__control">
                            <span class="waf-main-switch__label">检测强度</span>
                            <el-radio-group
                                v-model="siteStrict"
                                class="compact-segment"
                                :disabled="waf.state !== 'on' || globalStrict !== 'on'"
                                @change="setStrict"
                            >
                                <el-radio-button value="off">标准模式</el-radio-button>
                                <el-radio-button value="on">严格</el-radio-button>
                            </el-radio-group>
                            <el-alert
                                v-if="globalStrict !== 'on'"
                                type="warning"
                                :closable="false"
                                title="需要先在全局设置中开启严格模式"
                                class="inline-alert"
                            />
                        </div>
                    </div>
                </div>

                <!-- 频率限制 -->
                <div v-if="tab === '0'">
                    <ConfigCard header="访问频率限制" :description="ccDesc">
                        <template #header-r>
                            <el-switch
                                v-model="cfg.cc.state"
                                active-value="on"
                                inactive-value="off"
                                @change="(v) => toggleScope('cc', v)"
                            />
                        </template>
                        <template #content-form>
                            <el-form :model="cfg.cc" label-position="left" inline>
                                <el-form-item label="模式">
                                    <el-select v-model="cfg.cc.mode" class="p-w-200">
                                        <el-option label="全局模式" value="global" />
                                        <el-option label="URL 模式" value="uri" />
                                    </el-select>
                                </el-form-item>
                                <el-form-item label="周期">
                                    <el-input-number
                                        v-model="cfg.cc.duration"
                                        :min="10"
                                        :max="9999"
                                        controls-position="right"
                                        class="p-w-150"
                                    />
                                    <span class="unit">秒</span>
                                </el-form-item>
                                <el-form-item label="频率">
                                    <el-input-number
                                        v-model="cfg.cc.threshold"
                                        :min="1"
                                        :max="99999999"
                                        controls-position="right"
                                        class="p-w-150"
                                    />
                                    <span class="unit">次</span>
                                </el-form-item>
                                <el-form-item label="封禁时间">
                                    <el-input-number
                                        v-model="cfg.cc.ipBlockTime"
                                        :min="10"
                                        :max="99999999"
                                        controls-position="right"
                                        class="p-w-150"
                                    />
                                    <span class="unit">秒</span>
                                </el-form-item>
                                <el-form-item>
                                    <el-button @click="saveSite('访问频率限制')">保存</el-button>
                                </el-form-item>
                            </el-form>
                            <el-alert
                                type="info"
                                :closable="false"
                                title="全局模式：单位时间请求任意 URL 次数之和超过阈值即触发；URL 模式：单位时间请求单个 URL 次数超过阈值即触发"
                            />
                        </template>
                    </ConfigCard>
                </div>

                <!-- 默认规则 -->
                <div v-if="tab === '1'">
                    <ConfigCard
                        v-for="it in defaultCards"
                        :key="it.scope"
                        :header="it.label"
                        :description="it.desc"
                        class="mb-1.5"
                    >
                        <template #header-r>
                            <el-switch
                                v-model="cfg[it.scope].state"
                                active-value="on"
                                inactive-value="off"
                                @change="(v) => toggleScope(it.scope, v)"
                            />
                        </template>
                        <template v-if="countOf(it.file)" #content-form>
                            <div class="rule-line">
                                <span class="rule-count">
                                    已启用 <b>{{ countOf(it.file).enabled }}</b> / 共
                                    {{ countOf(it.file).total }} 条
                                </span>
                            </div>
                        </template>
                    </ConfigCard>
                </div>

                <!-- 自定义规则 -->
                <div v-if="tab === '2'">
                    <ConfigCard
                        header="自定义规则"
                        description="仅对当前网站生效，与全局默认规则互不影响"
                        class="mb-1.5"
                    >
                        <template #content-form>
                            <RuleInline
                                scope="site"
                                :site-key="curKey"
                                only-custom
                                :files="['defaultUrlBlack', 'defaultUaBlack', 'header', 'cookie', 'args', 'methodWhite']"
                                @changed="loadConfig"
                            />
                        </template>
                    </ConfigCard>

                    <ConfigCard
                        v-for="it in customCards"
                        :key="it.scope"
                        :header="it.label"
                        :description="it.desc"
                        class="mb-1.5"
                    >
                        <template #header-r>
                            <el-switch
                                v-model="cfg[it.scope].state"
                                active-value="on"
                                inactive-value="off"
                                @change="(v) => toggleScope(it.scope, v)"
                            />
                        </template>
                        <template v-if="it.panel" #content-form>
                            <div class="rule-line">
                                <span class="rule-count">{{ summaryOf(it.scope) }}</span>
                                <el-button link type="primary" @click="togglePanel(it.scope)">
                                    {{ openPanels[it.scope] ? '收起策略' : '配置策略' }}
                                </el-button>
                            </div>
                            <GeoPanel
                                v-if="openPanels[it.scope] && it.panel === 'geo'"
                                scope="site"
                                :site-key="curKey"
                                :active="!!openPanels[it.scope]"
                                @saved="loadConfig"
                            />
                            <CdnPanel
                                v-else-if="openPanels[it.scope] && it.panel === 'cdn'"
                                scope="site"
                                :site-key="curKey"
                                :active="!!openPanels[it.scope]"
                                @saved="loadConfig"
                            />
                        </template>
                        <template v-else-if="it.file" #content-form>
                            <RuleInline
                                scope="site"
                                :site-key="curKey"
                                :files="[it.file.replace('.json', '')]"
                                @changed="loadConfig"
                            />
                        </template>
                    </ConfigCard>
                </div>
            </div>
        </template>
    </LayoutContent>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import ConfigCard from '@/components/config-card/index.vue';
import GeoPanel from './geo-panel.vue';
import CdnPanel from './cdn-panel.vue';
import RuleInline from './rule-inline.vue';
import { getWafSiteConfig, getWafSiteList, saveWafSiteConfig, setWafState } from '@/api/modules/waf-log';

const props = defineProps<{ siteKey: string }>();
defineEmits<{ (e: 'back'): void }>();

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const router = useRouter();
const loading = ref(false);
const curKey = ref(props.siteKey);
const sites = ref<any[]>([]);
const emptyCfg = () => ({
    waf: { state: 'off', mode: 'protection' },
    args: { state: 'off' },
    cookie: { state: 'off' },
    header: { state: 'off' },
    methodWhite: { state: 'off' },
    defaultUaBlack: { state: 'off' },
    defaultUrlBlack: { state: 'off' },
    sql: { state: 'off' },
    xss: { state: 'off' },
    strict: { state: 'off' },
    fileExt: { state: 'off' },
    geoRestrict: { state: 'off', action: 'deny', rules: [], provinceRules: [] },
    cdn: { state: 'off', type: 'headers', rules: [] },
    cc: { state: 'off', duration: 10, threshold: 100, ipBlockTime: 600, mode: 'uri' },
});
const cfg = ref<any>(emptyCfg());
const rules = ref<any[]>([]);
const tab = ref(localStorage.getItem('waf-website-tab') || '0');
const globalStrict = ref('off');
const siteStrict = ref('off');

const waf = computed(() => cfg.value.waf || { state: 'off', mode: 'protection' });

const defaultCards = [
    { scope: 'args', label: '参数规则', file: 'args.json', desc: '禁止请求中携带恶意参数' },
    { scope: 'defaultUrlBlack', label: 'URL 规则', file: 'defaultUrlBlack.json', desc: '禁止访问的 URL' },
    { scope: 'methodWhite', label: 'HTTP 规则', file: 'methodWhite.json', desc: '设置允许访问的方法类型，关闭即可禁止该类方法' },
    { scope: 'cookie', label: 'Cookie 规则', file: 'cookie.json', desc: '禁止请求中携带恶意 Cookie' },
    { scope: 'header', label: 'Header 规则', file: 'header.json', desc: '禁止请求中携带恶意 Header' },
    { scope: 'defaultUaBlack', label: 'User-Agent 规则', file: 'defaultUaBlack.json', desc: '包含常见的恶意爬虫规则' },
    { scope: 'sql', label: 'SQL 注入防御', file: '', desc: '识别请求中的 SQL 注入并拦截' },
    { scope: 'xss', label: 'XSS 防御', file: '', desc: '识别请求中的 XSS 并拦截' },
    { scope: 'strict', label: '严格模式', file: '', desc: '使用更严格的规则来校验请求' },
];

const customCards = [
    { scope: 'fileExt', label: '文件上传限制', file: 'fileExt.json', desc: '禁止上传的文件扩展名' },
    { scope: 'geoRestrict', label: '地区访问限制', file: '', panel: 'geo', desc: '按国家/省份限制访问，全局开关为总开关' },
    { scope: 'cdn', label: 'CDN', file: 'cdn.json', panel: 'cdn', desc: '使用 CDN 的网站可以打开此处来获取正确来源 IP' },
];

const openPanels = ref<Record<string, boolean>>({});

const togglePanel = (scope: string) => {
    openPanels.value = { ...openPanels.value, [scope]: !openPanels.value[scope] };
};

const geoCN = computed(() => {
    const g: any = cfg.value.geoRestrict || {};
    return { rules: (g.rules || []).length, prov: (g.provinceRules || []).length, action: g.action || 'deny' };
});

const summaryOf = (scope: string) => {
    if (scope === 'geoRestrict') {
        const g = geoCN.value;
        if (!g.rules && !g.prov) return '尚未选择国家/省份';
        const a = g.action === 'allow' ? '仅允许' : '拦截';
        return `${a}：${g.rules} 个国家/地区${g.prov ? `、${g.prov} 个省份` : ''}`;
    }
    if (scope === 'cdn') {
        const c: any = cfg.value.cdn || {};
        const map: Record<string, string> = {
            headers: '按请求头列表',
            header: '指定单个请求头',
            xff: 'X-Forwarded-For 最后一段',
            xff2: 'X-Forwarded-For 倒数第二段',
            xff3: 'X-Forwarded-For 倒数第三段',
        };
        return `获取方式：${map[c.type] || '按请求头列表'}`;
    }
    return '';
};

const countOf = (file: string) => {
    if (!file) return null;
    const hit = (rules.value || []).find((r: any) => r.file === file);
    return hit ? { total: hit.total, enabled: hit.enabled } : null;
};

const ccDesc = computed(() => {
    const m = cfg.value.cc || {};
    return `${m.duration || 0} 秒内累计请求任意网站超过 ${m.threshold || 0} 次，封锁此 IP ${fmt(m.ipBlockTime)}`;
});

const fmt = (sec: number) => {
    const n = Number(sec || 0);
    if (!n) return '0 秒';
    if (n % 86400 === 0) return `${n / 86400} 天`;
    if (n % 3600 === 0) return `${n / 3600} 小时`;
    if (n % 60 === 0) return `${n / 60} 分钟`;
    return `${n} 秒`;
};

const loadSites = async () => {
    try {
        const d = unwrap(await getWafSiteList());
        sites.value = d.sites || [];
        globalStrict.value = d.global_strict || 'off';
    } catch {
        sites.value = [];
    }
};

const loadConfig = async () => {
    loading.value = true;
    try {
        const d = unwrap(await getWafSiteConfig(curKey.value));
        const c = d.config || {};
        const need = ['waf', 'args', 'cookie', 'header', 'methodWhite', 'defaultUaBlack', 'defaultUrlBlack', 'sql', 'xss', 'strict', 'fileExt', 'geoRestrict', 'cdn', 'app', 'cc'];
        need.forEach((k) => {
            if (!c[k] || typeof c[k] !== 'object') c[k] = { state: 'off' };
        });
        if (!c.waf.mode) c.waf.mode = 'protection';
        if (c.cc.duration == null) c.cc.duration = 10;
        if (c.cc.threshold == null) c.cc.threshold = 100;
        if (c.cc.ipBlockTime == null) c.cc.ipBlockTime = 600;
        if (!c.cc.mode) c.cc.mode = 'uri';
        cfg.value = c;
        siteStrict.value = c.strict.state === 'on' ? 'on' : 'off';
        rules.value = d.rules || [];
    } catch (e: any) {
        ElMessage.error('读取站点配置失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const onSiteChange = async (v: any) => {
    curKey.value = String(v);
    router.replace({ path: '/waf-log/site', query: { key: curKey.value } });
    await loadConfig();
};

const refreshBoth = async () => {
    await Promise.all([loadConfig(), loadSites()]);
};

const toggleScope = async (scope: string, v: any) => {
    const state = String(v);
    try {
        await setWafState({ key: curKey.value, scope, state });
        ElMessage.success('操作成功');
        await refreshBoth();
    } catch {
        await refreshBoth();
    }
};

const toggleWaf = async (v: any) => {
    const state = String(v);
    if (state === 'off') {
        try {
            await ElMessageBox.confirm('关闭 WAF 会使网站失去防护，是否继续', '关闭 WAF', {
                confirmButtonText: '确认',
                cancelButtonText: '取消',
                type: 'warning',
            });
        } catch {
            await refreshBoth();
            return;
        }
    }
    await toggleScope('waf', state);
};

const setMode = async (v: any) => {
    const mode = String(v);
    if (mode === 'observation') {
        try {
            await ElMessageBox.confirm(
                '开启观察模式后，所有 WAF 命中都只记录日志，不会拦截请求，是否继续？',
                '观察模式',
                { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' },
            );
        } catch {
            cfg.value.waf.mode = 'protection';
            return;
        }
    }
    try {
        await setWafState({ key: curKey.value, scope: 'waf', state: cfg.value.waf.state, mode });
        ElMessage.success('操作成功');
        await refreshBoth();
    } catch {
        await refreshBoth();
    }
};

const setStrict = async (v: any) => {
    await toggleScope('strict', v);
};

const saveSite = async (label: string) => {
    loading.value = true;
    try {
        const res = await saveWafSiteConfig({ key: curKey.value, config: cfg.value, reload: true });
        const d = res?.data || {};
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning(`${label}已写盘，但重载失败：${d.reload_error}`);
        } else {
            ElMessage.success(`${label}已保存`);
        }
        await refreshBoth();
    } catch (e: any) {
        ElMessage.error(e?.message || '保存失败');
    } finally {
        loading.value = false;
    }
};

watch(tab, (v) => localStorage.setItem('waf-website-tab', v));

// 父级通过 ?key= 切换站点时，详情页跟着刷新
watch(
    () => props.siteKey,
    (v) => {
        if (v && v !== curKey.value) {
            curKey.value = v;
            loadConfig();
        }
    },
);

onMounted(async () => {
    await Promise.all([loadSites(), loadConfig()]);
});
</script>

<style scoped>
.waf-main-switch {
    border: 1px solid var(--el-border-color-light);
    border-left: 4px solid var(--el-color-primary);
    background: var(--el-fill-color-extra-light);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    margin-bottom: 10px;
    padding: 14px 18px;
}
.waf-main-switch__header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    width: 100%;
}
.waf-main-switch__info {
    min-width: 0;
}
.waf-main-switch__title {
    color: var(--el-text-color-primary);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    font-size: 16px;
    font-weight: 600;
    line-height: 22px;
}
.waf-main-switch__mark {
    background: var(--el-color-primary);
    border-radius: 50%;
    width: 8px;
    height: 8px;
}
.waf-main-switch__description {
    color: var(--el-text-color-secondary);
    margin-top: 6px;
    font-size: 13px;
    line-height: 20px;
    display: block;
}
.waf-main-switch__controls {
    border-top: 1px solid var(--el-border-color-light);
    width: 100%;
    padding-top: 14px;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px 24px;
}
.waf-main-switch__control {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    min-width: 0;
}
.waf-main-switch__label {
    color: var(--el-text-color-primary);
    flex: 0 0 72px;
    font-size: 14px;
    font-weight: 500;
}
.inline-alert {
    padding: 2px 8px;
    width: auto;
    --el-alert-padding: 2px 8px;
}
.compact-segment {
    white-space: nowrap;
}
.compact-segment :deep(.el-radio-button__inner) {
    padding: 6px 10px;
    border: 1px solid var(--el-border-color);
    border-left-width: 0;
    outline: none;
}
.compact-segment :deep(.el-radio-button:first-child .el-radio-button__inner) {
    border-left-width: 1px;
}
.rule-line {
    display: flex;
    align-items: center;
    gap: 16px;
}
.rule-count {
    color: var(--el-text-color-secondary);
    font-size: 13px;
}
.rule-count b {
    color: var(--el-color-primary);
}
.unit {
    margin-left: 6px;
    color: var(--el-text-color-secondary);
    font-size: 13px;
}
.p-w-150 {
    width: 150px;
}
.p-w-200 {
    width: 200px;
}
.mb-1\.5 {
    margin-bottom: 6px;
}
</style>
