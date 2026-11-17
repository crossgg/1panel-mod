<template>
    <LayoutContent title="黑白名单" :divider="true">
        <template #leftToolBar>
            <el-button type="primary" :plain="cat !== 'ip'" @click="switchCat('ip')">IP</el-button>
            <el-button type="primary" :plain="cat !== 'url'" @click="switchCat('url')">URL</el-button>
            <el-button type="primary" :plain="cat !== 'ua'" @click="switchCat('ua')">User-Agent</el-button>
        </template>
        <template #main>
            <el-tabs v-model="side" tab-position="left" class="bw-tabs" @tab-change="onSideChange">
                <el-tab-pane label="黑名单" name="0">
                    <div class="waf-rule-toolbar">
                        <el-button type="primary" @click="openCreate">创建</el-button>
                        <el-button @click="openImport">导入</el-button>
                        <el-button :disabled="!rows.length" @click="doExport">导出</el-button>
                        <el-switch
                            class="ml-5"
                            :model-value="stateOf(kindOf('0'))"
                            active-value="on"
                            inactive-value="off"
                            @change="(v) => toggleScope(kindOf('0'), v)"
                        />
                        <el-alert type="info" :closable="false" class="waf-rule-description">
                            {{ helperOf(kindOf('0')) }}
                        </el-alert>
                    </div>
                    <el-table v-loading="loading" :data="rows" :height="tableHeight">
                        <el-table-column label="规则" prop="rule" min-width="260" show-overflow-tooltip>
                            <template #default="{ row }">{{ displayOf(row) }}</template>
                        </el-table-column>
                        <el-table-column label="状态" width="120">
                            <template #default="{ row }">
                                <el-switch
                                    :model-value="row.state"
                                    active-value="on"
                                    inactive-value="off"
                                    @change="(v) => setRowState(row, v)"
                                />
                            </template>
                        </el-table-column>
                        <el-table-column label="备注" prop="name" min-width="180" show-overflow-tooltip />
                        <el-table-column label="操作" width="140" fixed="right">
                            <template #default="{ row, $index }">
                                <el-button link type="primary" @click="openEdit(row, $index)">编辑</el-button>
                                <el-button link type="primary" @click="removeAt($index)">删除</el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </el-tab-pane>

                <el-tab-pane label="白名单" name="1">
                    <div class="waf-rule-toolbar">
                        <el-button type="primary" @click="openCreate">创建</el-button>
                        <el-button @click="openImport">导入</el-button>
                        <el-button :disabled="!rows.length" @click="doExport">导出</el-button>
                        <el-switch
                            class="ml-5"
                            :model-value="stateOf(kindOf('1'))"
                            active-value="on"
                            inactive-value="off"
                            @change="(v) => toggleScope(kindOf('1'), v)"
                        />
                        <el-alert type="info" :closable="false" class="waf-rule-description">
                            {{ helperOf(kindOf('1')) }}
                        </el-alert>
                    </div>
                    <el-table v-loading="loading" :data="rows" :height="tableHeight">
                        <el-table-column label="规则" prop="rule" min-width="260" show-overflow-tooltip>
                            <template #default="{ row }">{{ displayOf(row) }}</template>
                        </el-table-column>
                        <el-table-column label="状态" width="120">
                            <template #default="{ row }">
                                <el-switch
                                    :model-value="row.state"
                                    active-value="on"
                                    inactive-value="off"
                                    @change="(v) => setRowState(row, v)"
                                />
                            </template>
                        </el-table-column>
                        <el-table-column label="备注" prop="name" min-width="180" show-overflow-tooltip />
                        <el-table-column label="操作" width="140" fixed="right">
                            <template #default="{ row, $index }">
                                <el-button link type="primary" @click="openEdit(row, $index)">编辑</el-button>
                                <el-button link type="primary" @click="removeAt($index)">删除</el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </el-tab-pane>
            </el-tabs>

            <!-- 创建 / 编辑 -->
            <el-dialog v-model="opVisible" :title="opIndex >= 0 ? '编辑' : '创建'" width="520px" destroy-on-close>
                <el-form :model="opForm" label-position="top">
                    <el-form-item label="规则" required>
                        <el-input
                            v-model="opForm.rule"
                            :placeholder="placeholderOf(activeKind)"
                            spellcheck="false"
                        />
                        <div class="input-help">{{ hintOf(activeKind) }}</div>
                    </el-form-item>
                    <el-form-item label="备注">
                        <el-input v-model="opForm.name" placeholder="选填，便于识别" />
                    </el-form-item>
                </el-form>
                <template #footer>
                    <el-button @click="opVisible = false">取消</el-button>
                    <el-button type="primary" :loading="saving" @click="commitOp">确认</el-button>
                </template>
            </el-dialog>

            <!-- 导入 -->
            <el-dialog v-model="importVisible" title="导入" width="600px" destroy-on-close>
                <el-alert type="info" :closable="false" title="一行一个规则，可用 Tab 或空格分隔备注" class="mb" />
                <el-input
                    v-model="importText"
                    type="textarea"
                    :rows="12"
                    spellcheck="false"
                    :placeholder="importExample(activeKind)"
                />
                <template #footer>
                    <el-button @click="importVisible = false">取消</el-button>
                    <el-button type="primary" :loading="saving" @click="doImport">导入并生效</el-button>
                </template>
            </el-dialog>
        </template>
    </LayoutContent>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import {
    getWafBwList,
    getWafBwSummary,
    importWafBw,
    saveWafBw,
    setWafState,
} from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});
const route = useRoute();

const cat = ref('ip');
const side = ref('0');
const loading = ref(false);
const saving = ref(false);
const rows = ref<any[]>([]);
const summary = ref<any[]>([]);
const opVisible = ref(false);
const importVisible = ref(false);
const importText = ref('');
const opIndex = ref(-1);
const opForm = reactive({ rule: '', name: '' });
const tableHeight = ref<string | number>(520);

const kindOf = (sd: string) => {
    const cap = cat.value === 'ua' ? 'ua' : cat.value;
    return cap + (sd === '0' ? 'Black' : 'White');
};
const activeKind = computed(() => kindOf(side.value));

const helperOf = (kind: string) => {
    if (kind === 'ipBlack') return '黑名单中的 IP 无法访问网站';
    if (kind === 'ipWhite') return '白名单中的 IP 不受任何规则限制';
    if (kind === 'uaBlack') return '携带黑名单中的 User-Agent 的请求将被拦截';
    if (kind === 'uaWhite') return '携带白名单中的 User-Agent 的请求不受任何规则限制';
    if (kind === 'urlBlack') return '请求黑名单中的 URL 将被拦截';
    return '请求白名单中的 URL 不受任何规则限制';
};

const isIp = computed(() => cat.value === 'ip');
const hintOf = (kind: string) => {
    if (kind.startsWith('ip')) return '支持单 IP、CIDR（如 10.0.0.0/24）、区间（如 10.0.0.1-10.0.0.50）';
    if (kind.startsWith('url')) return '匹配请求 URI，支持正则；如 /admin 或 \\.php$';
    return '匹配 User-Agent，支持正则；如 sqlmap 或 BadBot|Scanner';
};
const placeholderOf = (kind: string) => {
    if (kind.startsWith('ip')) return '例如 10.0.0.0/24 或 1.2.3.4';
    if (kind.startsWith('url')) return '例如 /admin 或 \\.php$';
    return '例如 sqlmap 或 BadBot|Scanner';
};
const importExample = (kind: string) => {
    if (kind.startsWith('ip')) return '10.0.0.0/24\t内网段\n1.2.3.4\t恶意扫描';
    if (kind.startsWith('url')) return '/admin\t后台路径\n\\.php$\t禁止访问 php';
    return 'sqlmap\t扫描器\nBadBot|Scanner\t爬虫';
};

const displayOf = (row: any) => {
    if (row.start && row.end) {
        return row.start === row.end ? row.start : `${row.start} - ${row.end}`;
    }
    return row.rule || '';
};

const stateOf = (kind: string) => {
    const it = summary.value.find((s: any) => s.kind === kind);
    return it ? it.state : 'on';
};

const loadSummary = async () => {
    try {
        const d = unwrap(await getWafBwSummary());
        summary.value = d.items || [];
    } catch {
        summary.value = [];
    }
};

const loadRows = async () => {
    loading.value = true;
    try {
        const d = unwrap(await getWafBwList(activeKind.value));
        rows.value = (d.entries || []).map((e: any) => ({
            state: e.state || 'on',
            name: e.name || '',
            rule: e.rule || '',
            start: e.start || '',
            end: e.end || '',
            type: e.type || '',
        }));
    } catch (e: any) {
        rows.value = [];
        ElMessage.error('读取失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const loadAll = async () => {
    await Promise.all([loadSummary(), loadRows()]);
};

const switchCat = async (c: string) => {
    if (cat.value === c) return;
    cat.value = c;
    side.value = '0';
    await loadAll();
};

const onSideChange = async () => {
    await loadRows();
};

const persist = async (silent = false) => {
    saving.value = true;
    try {
        const entries = rows.value.map((r) => ({
            state: r.state,
            name: r.name,
            rule: r.rule,
            start: r.start,
            end: r.end,
            type: r.type,
        }));
        const d = unwrap(await saveWafBw({ kind: activeKind.value, entries, reload: true }));
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning('已保存，但重载 OpenResty 失败');
        } else if (!silent) {
            ElMessage.success('操作成功');
        }
        await loadAll();
        return true;
    } catch (e: any) {
        ElMessage.error('保存失败：' + (e?.message || e));
        return false;
    } finally {
        saving.value = false;
    }
};

const setRowState = async (row: any, v: any) => {
    row.state = String(v);
    await persist(true);
};

const removeAt = async (idx: number) => {
    try {
        await ElMessageBox.confirm(`删除规则「${displayOf(rows.value[idx])}」？`, '删除', {
            confirmButtonText: '确认',
            cancelButtonText: '取消',
            type: 'warning',
        });
    } catch {
        return;
    }
    rows.value.splice(idx, 1);
    await persist();
};

const openCreate = () => {
    opIndex.value = -1;
    opForm.rule = '';
    opForm.name = '';
    opVisible.value = true;
};

const openEdit = (row: any, idx: number) => {
    opIndex.value = idx;
    opForm.rule = displayOf(row);
    opForm.name = row.name;
    opVisible.value = true;
};

const commitOp = async () => {
    const v = (opForm.rule || '').trim();
    if (!v) {
        ElMessage.warning('规则不能为空');
        return;
    }
    if (isIp.value && !/^[0-9a-fA-F.:]+(\/\d{1,2})?$|^[0-9.]+-[0-9.]+$/.test(v)) {
        ElMessage.warning('看起来不是合法的 IP / CIDR / 区间');
        return;
    }
    if (opIndex.value >= 0) {
        const row = rows.value[opIndex.value];
        row.rule = v;
        row.name = opForm.name;
        // 编辑 IP 时清掉旧的区间，交给后端重新解析
        row.start = '';
        row.end = '';
    } else {
        rows.value.push({ state: 'on', name: opForm.name, rule: v, start: '', end: '', type: '' });
    }
    opVisible.value = false;
    await persist();
};

const openImport = () => {
    importText.value = '';
    importVisible.value = true;
};

const doImport = async () => {
    if (!importText.value.trim()) {
        ElMessage.warning('内容为空');
        return;
    }
    saving.value = true;
    try {
        const d = unwrap(
            await importWafBw({ kind: activeKind.value, text: importText.value, state: 'on', reload: true }),
        );
        const parts = [`新增 ${d.added ?? 0} 条`];
        if (d.skipped) parts.push(`跳过重复 ${d.skipped} 条`);
        if ((d.failed || []).length) parts.push(`失败 ${d.failed.length} 条`);
        ElMessage.success(parts.join('，'));
        importVisible.value = false;
        await loadAll();
    } catch (e: any) {
        ElMessage.error('导入失败：' + (e?.message || e));
    } finally {
        saving.value = false;
    }
};

const doExport = () => {
    const lines = rows.value.map((r) => (r.name ? `${displayOf(r)}\t${r.name}` : displayOf(r)));
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = activeKind.value + '.txt';
    a.dispatchEvent(new MouseEvent('click'));
    window.URL.revokeObjectURL(url);
};

// 名单整体开关（全局 scope：ipBlack/ipWhite/...）
const toggleScope = async (kind: string, v: any) => {
    const target = String(v);
    try {
        const res = await setWafState({ scope: kind, state: target });
        const d = res?.data || {};
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning(`已写盘，但重载失败：${d.reload_error}`);
        } else {
            ElMessage.success('操作成功');
        }
        await loadSummary();
    } catch {
        await loadSummary();
    }
};

onMounted(async () => {
    const q = String(route.query.kind || '');
    if (q.startsWith('ip')) {
        cat.value = 'ip';
        side.value = q === 'ipWhite' ? '1' : '0';
    } else if (q.startsWith('url')) {
        cat.value = 'url';
        side.value = q === 'urlWhite' ? '1' : '0';
    } else if (q.startsWith('ua')) {
        cat.value = 'ua';
        side.value = q === 'uaWhite' ? '1' : '0';
    }
    await loadAll();
});
</script>

<style scoped lang="scss">
.bw-tabs {
    min-height: 460px;
}
.waf-rule-toolbar {
    display: flex;
    justify-content: flex-start;
    align-items: center;
    margin-bottom: 20px;
}
.waf-rule-description {
    margin-left: 20px;
    --el-alert-padding: 4px 12px;
    width: auto;
}
.ml-5 {
    margin-left: 20px;
}
.input-help {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    line-height: 18px;
    margin-top: 4px;
}
.mb {
    margin-bottom: 10px;
}
</style>
