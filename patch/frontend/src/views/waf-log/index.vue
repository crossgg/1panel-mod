<template>
    <div class="waf-log-page">
        <el-alert v-if="errorMsg" :title="errorMsg" type="error" show-icon :closable="false" class="mb" />

        <el-row :gutter="12" class="mb">
            <el-col v-for="card in statCards" :key="card.key" :span="4">
                <el-card shadow="never" class="stat-card">
                    <div class="stat-label">{{ card.label }}</div>
                    <div class="stat-value" :class="{ danger: card.key === 'attack_count' }">{{ card.value }}</div>
                </el-card>
            </el-col>
        </el-row>

        <el-card shadow="never">
            <template #header>
                <div class="card-header">
                    <span class="title">WAF 日志</span>
                    <span class="source">数据源：{{ sourceInfo }}</span>
                    <el-button size="small" :disabled="!total" @click="doExport">导出</el-button>
                    <el-button size="small" type="danger" plain @click="doClear">清空</el-button>
                    <el-button size="small" @click="loadAll">刷新</el-button>
                </div>
            </template>

            <el-tabs v-model="tab">
                <el-tab-pane label="拦截记录" name="waf" />
                <el-tab-pane v-if="hasSiteLogs" label="站点流量日志 (v2)" name="site" />
            </el-tabs>

            <div class="filters">
                <el-select
                    v-model="filters.website_key"
                    clearable
                    placeholder="网站"
                    style="width: 200px"
                    @change="search"
                >
                    <el-option
                        v-for="item in sites"
                        :key="item.website_key"
                        :label="item.website_key"
                        :value="item.website_key"
                    />
                </el-select>
                <el-select
                    v-if="tab === 'waf'"
                    v-model="filters.exec_rule"
                    clearable
                    placeholder="命中规则"
                    style="width: 200px"
                    @change="search"
                >
                    <el-option v-for="item in rules" :key="item.value" :label="item.label" :value="item.value" />
                </el-select>
                <el-input
                    v-model="filters.uri"
                    clearable
                    placeholder="URL 模糊搜索"
                    style="width: 220px"
                    @keyup.enter="search"
                />
                <el-input
                    v-model="filters.ip"
                    clearable
                    placeholder="IP 精确搜索"
                    style="width: 170px"
                    @keyup.enter="search"
                />
                <el-checkbox v-if="tab === 'waf'" v-model="filters.only_attack" @change="search">只看拦截</el-checkbox>
                <el-button type="primary" @click="search">搜索</el-button>
                <el-button @click="reset">重置</el-button>
            </div>

            <el-table v-loading="loading" :data="rows" stripe size="small" style="width: 100%">
                <template v-if="tab === 'waf'">
                    <el-table-column prop="localtime" label="时间" width="170" />
                    <el-table-column prop="ip" label="IP" width="140" />
                    <el-table-column label="域名" min-width="170" show-overflow-tooltip>
                        <template #default="{ row }">{{ siteLabel(row) }}</template>
                    </el-table-column>
                    <el-table-column label="URL" min-width="260" show-overflow-tooltip>
                        <template #default="{ row }">{{ row.uri || row.req_uri || '-' }}</template>
                    </el-table-column>
                    <el-table-column label="归属地" width="140">
                        <template #default="{ row }">
                            {{ [row.ip_country_zh, row.ip_province_zh].filter(Boolean).join(' ') }}
                        </template>
                    </el-table-column>
                    <el-table-column label="动作" width="90">
                        <template #default="{ row }">
                            <el-tag :type="row.action === 'deny' ? 'danger' : 'success'" size="small">
                                {{ row.action === 'deny' ? '禁止' : '允许' }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="状态" width="80">
                        <template #default="{ row }">{{ row.status_code ?? '-' }}</template>
                    </el-table-column>
                    <el-table-column prop="exec_rule" label="命中规则" min-width="140" />
                    <el-table-column prop="rule_type" label="类型" min-width="110" />
                    <el-table-column fixed="right" label="操作" width="80">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="openDetail(row)">详情</el-button>
                        </template>
                    </el-table-column>
                </template>
                <template v-else>
                    <el-table-column prop="localtime" label="时间" width="170" />
                    <el-table-column prop="ip" label="IP" width="140" />
                    <el-table-column prop="method" label="方法" width="90" />
                    <el-table-column prop="uri" label="URL" min-width="300" show-overflow-tooltip />
                    <el-table-column label="状态" width="100">
                        <template #default="{ row }">{{ row.status_code ?? row.status }}</template>
                    </el-table-column>
                    <el-table-column prop="request_time" label="耗时" width="110" />
                    <el-table-column prop="browser" label="浏览器" min-width="140" />
                    <el-table-column prop="os" label="系统" min-width="140" />
                </template>
                <template #empty>
                    <el-empty description="暂无日志数据" :image-size="70" />
                </template>
            </el-table>

            <div class="pager">
                <el-pagination
                    v-model:current-page="page"
                    v-model:page-size="size"
                    :page-sizes="[10, 20, 50, 100]"
                    :total="total"
                    layout="total, sizes, prev, pager, next"
                    @current-change="loadList"
                    @size-change="search"
                />
            </div>
        </el-card>

        <el-drawer v-model="drawer" title="请求详情" size="45%">
            <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="时间">{{ current.localtime || '-' }}</el-descriptions-item>
                <el-descriptions-item label="攻击 IP">{{ current.ip || '-' }}</el-descriptions-item>
                <el-descriptions-item label="域名">{{ siteLabel(current) }}</el-descriptions-item>
                <el-descriptions-item label="归属地">
                    {{ [current.ip_country_zh, current.ip_province_zh].filter(Boolean).join(' ') || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="动作">{{ current.action || '-' }}</el-descriptions-item>
                <el-descriptions-item label="方法">{{ current.method || '-' }}</el-descriptions-item>
                <el-descriptions-item label="状态码">{{ current.status_code ?? '-' }}</el-descriptions-item>
                <el-descriptions-item label="命中规则">{{ current.exec_rule || '-' }}</el-descriptions-item>
                <el-descriptions-item label="类型">{{ current.rule_type || '-' }}</el-descriptions-item>
                <el-descriptions-item label="URI">{{ current.uri || '-' }}</el-descriptions-item>
                <el-descriptions-item label="原始 URI">{{ current.req_uri || '-' }}</el-descriptions-item>
                <el-descriptions-item label="匹配值">{{ decodeBase64(current.match_value) || '-' }}</el-descriptions-item>
                <el-descriptions-item label="User-Agent">{{ current.user_agent || '-' }}</el-descriptions-item>
                <el-descriptions-item label="来源库">{{ current._db || '-' }}</el-descriptions-item>
            </el-descriptions>
            <div class="sub-title">HTTP 请求原文</div>
            <pre class="raw">{{ current.nginx_log || '暂无日志数据' }}</pre>
        </el-drawer>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { clearWafLog, exportWafLogUrl } from '@/api/modules/waf-log';
import {
    getWafLogDiag,
    getWafLogList,
    getWafLogRules,
    getWafLogSiteLogs,
    getWafLogSites,
    getWafLogStat,
} from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

// 1pwaf 2.0 还没在面板里建站点时 website_key 一律是 unknown，
// 这时退回到 server_name / host，实在没有就显示“默认站点”。
const siteLabel = (row: any) => {
    const key = row?.website_key;
    if (key && key !== 'unknown') return key;
    return row?.server_name || row?.host || '默认站点';
};

const loading = ref(false);
const tab = ref('waf');
const page = ref(1);
const size = ref(10);
const total = ref(0);
const rows = ref<any[]>([]);
const sites = ref<any[]>([]);
const rules = ref<any[]>([]);
const hasSiteLogs = ref(false);
const sourceInfo = ref('探测中…');
const errorMsg = ref('');
const drawer = ref(false);
const current = ref<any>({});

const filters = reactive({
    website_key: '',
    exec_rule: '',
    uri: '',
    ip: '',
    only_attack: false,
});

const stat = reactive({
    req_count: 0,
    attack_count: 0,
    count4xx: 0,
    count5xx: 0,
    total_logs: 0,
});

const statCards = computed(() => [
    { key: 'req_count', label: '请求 / 站点日志', value: stat.req_count },
    { key: 'attack_count', label: '拦截', value: stat.attack_count },
    { key: 'count4xx', label: '4xx', value: stat.count4xx },
    { key: 'count5xx', label: '5xx', value: stat.count5xx },
    { key: 'total_logs', label: '拦截库记录', value: stat.total_logs },
]);

const decodeBase64 = (value: any) => {
    if (!value) return '';
    const raw = String(value);
    // 1pwaf 2.0 的 match_value 直接存明文（例如 1' or 1=1--），
    // 只有「看起来像 base64」的老库数据才尝试解码，否则原样返回，避免明文被误解码成乱码。
    if (raw.length < 8 || !/^[A-Za-z0-9+/=\s]+$/.test(raw)) return raw;
    try {
        const bin = atob(raw.replace(/\s/g, ''));
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        // 解出不可打印字符说明它本来就不是 base64，回退明文
        if (!text || /[\u0000-\u0008\u000e-\u001f\ufffd]/.test(text)) return raw;
        return text;
    } catch (e) {
        return raw;
    }
};

async function loadDiag() {
    try {
        const res: any = await getWafLogDiag();
        const data = unwrap(res);
        const sources = data.sources || [];
        const v2 = data.v2 || [];
        if (v2.length) {
            // 1pwaf 2.0：attack_logs + 维度库，没有 site_req_logs，隐藏站点日志页签
            hasSiteLogs.value = false;
            const files: string[] = v2.flatMap((v: any) => v.db_files || []);
            sourceInfo.value = `1pwaf 2.0 · ${v2[0].base} · ${files.length} 个库文件`;
            return;
        }
        hasSiteLogs.value = sources.some((s: any) => s.kind === 'sitelog');
        const files: string[] = [...new Set(sources.map((s: any) => s.file))];
        sourceInfo.value = files.length
            ? files.map((f: string) => f.split('/').pop()).join('、')
            : (data.found_dirs || []).join(' , ') || '未找到 WAF 数据库';
        if (!data.ok) {
            errorMsg.value = data.hint || '未找到 WAF 日志库，请检查 openresty 的 1pwaf/data/db';
        }
    } catch (e: any) {
        errorMsg.value = `诊断接口失败：${e?.message || e}`;
    }
}

async function loadStat() {
    try {
        const data: any = unwrap(await getWafLogStat());
        stat.req_count = Number(data.req_count) || 0;
        stat.attack_count = Number(data.attack_count) || 0;
        stat.count4xx = Number(data.count4xx) || 0;
        stat.count5xx = Number(data.count5xx) || 0;
        stat.total_logs = Number(data.total_logs) || 0;
    } catch (e: any) {
        errorMsg.value = `统计接口失败：${e?.message || e}`;
    }
}

async function loadSites() {
    try {
        const data: any = unwrap(await getWafLogSites(tab.value === 'site' ? 'site' : 'waf'));
        sites.value = data.data || [];
    } catch (e) {
        sites.value = [];
    }
}

async function loadRules() {
    try {
        const data: any = unwrap(await getWafLogRules());
        rules.value = data.data || [];
    } catch (e) {
        rules.value = [];
    }
}

async function loadList() {
    loading.value = true;
    try {
        const params: any = {
            page: page.value,
            size: size.value,
            uri: filters.uri,
            ip: filters.ip,
        };
        if (tab.value === 'waf') {
            params.website_key = filters.website_key;
            params.exec_rule = filters.exec_rule;
            params.only_attack = filters.only_attack ? 1 : '';
        } else {
            params.site = filters.website_key;
        }
        const res: any = tab.value === 'waf' ? await getWafLogList(params) : await getWafLogSiteLogs(params);
        const data: any = unwrap(res);
        rows.value = data.data || [];
        total.value = Number(data.total) || 0;
        if (data.warnings && data.warnings.length) {
            errorMsg.value = data.warnings.join('；');
        }
    } catch (e: any) {
        errorMsg.value = `日志加载失败：${e?.message || e}`;
        rows.value = [];
        total.value = 0;
    } finally {
        loading.value = false;
    }
}

function search() {
    page.value = 1;
    loadList();
}

function reset() {
    filters.website_key = '';
    filters.exec_rule = '';
    filters.uri = '';
    filters.ip = '';
    filters.only_attack = false;
    search();
}

function openDetail(row: any) {
    current.value = row;
    drawer.value = true;
}

async function loadAll() {
    errorMsg.value = '';
    await Promise.all([loadDiag(), loadStat(), loadSites(), loadRules(), loadList()]);
}

// 导出：把当前筛选条件带上去，后端直接吐 CSV
function doExport() {
    const q = new URLSearchParams();
    if (filters.website_key) q.set('website_key', filters.website_key);
    if (filters.exec_rule) q.set('exec_rule', filters.exec_rule);
    if (filters.uri) q.set('uri', filters.uri);
    if (filters.ip) q.set('ip', filters.ip);
    if (filters.only_attack) q.set('only_attack', '1');
    const url = q.toString() ? `${exportWafLogUrl}?${q.toString()}` : exportWafLogUrl;
    window.open(url, '_blank');
}

async function doClear() {
    try {
        await ElMessageBox.confirm('清空日志将无法恢复，是否继续？', '清空所有日志', {
            confirmButtonText: '确认清空',
            cancelButtonText: '取消',
            type: 'warning',
        });
    } catch {
        return;
    }
    try {
        const d = unwrap(await clearWafLog());
        const parts = Object.entries(d.deleted || {}).map(([k, v]) => `${k} ${v}`);
        ElMessage.success(parts.length ? `已清空：${parts.join('，')}` : '已清空');
        if ((d.warnings || []).length) ElMessage.warning(d.warnings.join('；'));
        await loadAll();
    } catch (e: any) {
        ElMessage.error('清空失败：' + (e?.message || e));
    }
}

watch(tab, () => {
    filters.website_key = '';
    page.value = 1;
    loadSites();
    loadList();
});

onMounted(() => {
    loadAll();
});
</script>

<style scoped>
.waf-log-page {
    padding: 4px 2px;
}
.mb {
    margin-bottom: 12px;
}
.stat-card {
    :deep(.el-card__body) {
        padding: 12px 14px;
    }
}
.stat-label {
    color: #646a73;
    font-size: 13px;
}
.stat-value {
    margin-top: 4px;
    font-size: 22px;
    font-weight: 500;
    color: #005eeb;
    line-height: 1.3;
}
.stat-value.danger {
    color: #d03050;
}
.card-header {
    display: flex;
    align-items: center;
    gap: 12px;
}
.card-header .title {
    font-weight: 500;
}
.card-header .source {
    flex: 1;
    color: #8a8f99;
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin: 4px 0 14px;
}
.pager {
    display: flex;
    justify-content: flex-end;
    margin-top: 14px;
}
.sub-title {
    margin: 18px 0 8px;
    font-weight: 500;
}
.raw {
    margin: 0;
    padding: 10px 12px;
    max-height: 360px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
    background: #f7f8fa;
    border: 1px solid #e5e6eb;
    border-radius: 6px;
    font-family: Consolas, Monaco, monospace;
    font-size: 12px;
    line-height: 1.6;
}
</style>
