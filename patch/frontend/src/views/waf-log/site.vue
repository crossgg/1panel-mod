<template>
    <SiteDetail v-if="activeKey" :site-key="activeKey" @back="closeDetail" />
    <LayoutContent v-else title="网站设置" :divider="true">
        <template #rightToolBar>
            <el-input
                v-model="search"
                class="website-search"
                placeholder="请输入网站域名、别名或备注"
                clearable
                style="width: 240px"
            />
            <el-button :loading="loading" @click="load">刷新</el-button>
        </template>
        <template #main>
            <div v-loading="loading">
                <el-alert
                    v-if="!loading && !sites.length"
                    title="请先创建网站"
                    type="info"
                    show-icon
                    :closable="false"
                />
                <el-table v-else :data="filtered" :height="540">
                    <el-table-column label="网站" prop="key" min-width="190" show-overflow-tooltip>
                        <template #default="{ row }">
                            <div>{{ row.key }}</div>
                            <div class="site-domains">{{ (row.domains || []).join(' , ') || '-' }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="备注" min-width="150" show-overflow-tooltip>
                        <template #default="{ row }">{{ (row.host || []).join(' , ') || '-' }}</template>
                    </el-table-column>
                    <el-table-column label="开关" min-width="130">
                        <template #default="{ row }">
                            <el-switch
                                :model-value="row.waf_state"
                                active-value="on"
                                inactive-value="off"
                                :loading="row.saving"
                                :disabled="row.saving"
                                @change="(v) => setWaf(row, v)"
                            />
                        </template>
                    </el-table-column>
                    <el-table-column label="执行策略" min-width="190">
                        <template #default="{ row }">
                            <el-radio-group
                                :model-value="row.waf_mode || 'protection'"
                                class="compact-segment"
                                :disabled="row.saving || row.waf_state !== 'on'"
                                @change="(v) => setMode(row, v)"
                            >
                                <el-radio-button value="protection">保护模式</el-radio-button>
                                <el-radio-button value="observation">观察模式</el-radio-button>
                            </el-radio-group>
                        </template>
                    </el-table-column>
                    <el-table-column label="检测强度" min-width="175">
                        <template #default="{ row }">
                            <el-tooltip
                                :disabled="globalStrict === 'on'"
                                content="需要先在全局设置中开启严格模式"
                            >
                                <el-radio-group
                                    :model-value="row.strict_state || 'off'"
                                    class="compact-segment"
                                    :disabled="row.saving || row.waf_state !== 'on' || globalStrict !== 'on'"
                                    @change="(v) => setStrict(row, v)"
                                >
                                    <el-radio-button value="off">标准模式</el-radio-button>
                                    <el-radio-button value="on">严格</el-radio-button>
                                </el-radio-group>
                            </el-tooltip>
                        </template>
                    </el-table-column>
                    <el-table-column label="频率限制" min-width="130">
                        <template #default="{ row }">
                            <el-switch
                                :model-value="row.cc_state"
                                active-value="on"
                                inactive-value="off"
                                :loading="row.saving"
                                :disabled="row.saving"
                                @change="(v) => setCc(row, v)"
                            />
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="110" fixed="right" align="center">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="openDetail(row)">详细设置</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </div>
        </template>
    </LayoutContent>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import SiteDetail from '@/views/waf-log/site-detail.vue';
import { getWafSiteList, setWafState } from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});
const route = useRoute();
const router = useRouter();

const loading = ref(false);
const sites = ref<any[]>([]);
const search = ref('');
const globalStrict = ref('off');
const activeKey = ref('');

const filtered = computed(() => {
    const kw = search.value.trim().toLowerCase();
    if (!kw) return sites.value;
    return sites.value.filter((s: any) => {
        const text = [s.key, ...(s.domains || []), ...(s.host || [])].join(' ').toLowerCase();
        return text.includes(kw);
    });
});

const load = async () => {
    loading.value = true;
    try {
        const d = unwrap(await getWafSiteList());
        sites.value = (d.sites || []).map((s: any) => ({ saving: false, ...s }));
        globalStrict.value = d.global_strict || 'off';
    } catch (e: any) {
        sites.value = [];
        ElMessage.error('读取站点失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const apply = async (row: any, payload: object, after?: () => void) => {
    row.saving = true;
    try {
        const res = await setWafState(payload);
        const d = res?.data || {};
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning(`已写盘，但重载失败：${d.reload_error}`);
        } else {
            ElMessage.success('操作成功');
        }
        if (after) after();
    } catch {
        await load();
    } finally {
        row.saving = false;
    }
};

const setWaf = async (row: any, v: any) => {
    const target = String(v);
    if (target === 'off') {
        try {
            await ElMessageBox.confirm('关闭 WAF 会使网站失去防护，是否继续', '关闭 WAF', {
                confirmButtonText: '确认',
                cancelButtonText: '取消',
                type: 'warning',
            });
        } catch {
            await load();
            return;
        }
    }
    await apply(row, { key: row.key, scope: 'waf', state: target }, () => (row.waf_state = target));
};

const setMode = async (row: any, v: any) => {
    const mode = String(v);
    if (mode === 'observation') {
        try {
            await ElMessageBox.confirm(
                '开启观察模式后，所有 WAF 命中都只记录日志，不会拦截请求，是否继续？',
                '观察模式',
                { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' },
            );
        } catch {
            await load();
            return;
        }
    }
    await apply(row, { key: row.key, scope: 'waf', state: row.waf_state, mode }, () => (row.waf_mode = mode));
};

const setStrict = async (row: any, v: any) => {
    const state = String(v);
    await apply(row, { key: row.key, scope: 'strict', state }, () => (row.strict_state = state));
};

const setCc = async (row: any, v: any) => {
    const state = String(v);
    await apply(row, { key: row.key, scope: 'cc', state }, () => (row.cc_state = state));
};

const openDetail = (row: any) => {
    activeKey.value = row.key;
    router.replace({ path: '/waf-log/site', query: { key: row.key } });
};

const closeDetail = () => {
    activeKey.value = '';
    router.replace({ path: '/waf-log/site' });
    load();
};

onMounted(async () => {
    const k = String(route.query.key || '');
    if (k) activeKey.value = k;
    await load();
});

// 详情页返回按钮走的是路由，这里同步一下列表/详情切换
watch(
    () => route.query.key,
    (k) => {
        activeKey.value = String(k || '');
    },
);
</script>

<style scoped lang="scss">
.site-domains {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    line-height: 16px;
}
.compact-segment {
    white-space: nowrap;
    :deep(.el-radio-button__inner) {
        padding: 6px 10px;
        border: 1px solid var(--el-border-color);
        border-left-width: 0;
        outline: none;
    }
    :deep(.el-radio-button:first-child .el-radio-button__inner) {
        border-left-width: 1px;
    }
}
</style>
