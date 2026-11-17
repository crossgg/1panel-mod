<template>
    <div class="waf-rule-page">
        <el-card shadow="never">
            <template #header>
                <div class="card-header">
                    <div>
                        <span class="title">自定义规则</span>
                        <span class="sub">
                            统一管理 1pwaf 规则库：可直接停用内置规则，也可新增自己的拦截规则（保存即生效）
                        </span>
                    </div>
                    <div class="ops">
                        <el-button size="small" :loading="loading" @click="loadAll">刷新</el-button>
                        <el-button size="small" type="primary" @click="openCreate">新增规则</el-button>
                    </div>
                </div>
            </template>

            <div class="filter-row">
                <el-select v-model="filter.file" size="small" style="width: 200px" @change="loadRules">
                    <el-option label="全部来源" value="" />
                    <el-option
                        v-for="f in files"
                        :key="f.file"
                        :label="`${f.label}（${f.enabled}/${f.count}）`"
                        :value="f.file"
                    />
                </el-select>
                <el-input
                    v-model="filter.kw"
                    size="small"
                    style="width: 260px"
                    placeholder="搜索名称 / 内容 / 类型"
                    clearable
                    @keyup.enter="loadRules"
                    @clear="loadRules"
                />
                <el-button size="small" @click="loadRules">搜索</el-button>
                <el-switch v-model="filter.onlyOn" size="small" active-text="只看启用" @change="loadRules" />
                <span class="count">共 {{ total }} 条</span>
            </div>

            <el-table
                v-loading="loading"
                :data="pageRows"
                size="small"
                stripe
                style="width: 100%"
                :row-key="rowKey"
            >
                <el-table-column label="来源" width="170">
                    <template #default="{ row }">
                        <div class="src">{{ row.label }}</div>
                        <div class="src-file">{{ row.file }}.json</div>
                    </template>
                </el-table-column>
                <el-table-column label="名称" width="150" show-overflow-tooltip>
                    <template #default="{ row }">
                        <span class="mono">{{ row.name || '-' }}</span>
                    </template>
                </el-table-column>
                <el-table-column label="匹配内容" min-width="300">
                    <template #default="{ row }">
                        <span class="mono rule-text">{{ row.rule }}</span>
                    </template>
                </el-table-column>
                <el-table-column label="类型" width="130">
                    <template #default="{ row }">
                        <el-tag size="small" type="info">{{ row.type || '-' }}</el-tag>
                    </template>
                </el-table-column>
                <el-table-column label="状态" width="80">
                    <template #default="{ row }">
                        <el-switch
                            v-if="row.file !== 'cdn'"
                            :model-value="row.state === 'on'"
                            @change="(v) => toggle(row, v)"
                        />
                        <span v-else class="tip">-</span>
                    </template>
                </el-table-column>
                <el-table-column label="操作" width="120" fixed="right">
                    <template #default="{ row }">
                        <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
                        <el-button link type="danger" @click="remove(row)">删除</el-button>
                    </template>
                </el-table-column>
            </el-table>

            <div class="pager">
                <el-pagination
                    v-model:current-page="page"
                    :page-size="pageSize"
                    :total="rows.length"
                    layout="prev, pager, next, total"
                    size="small"
                    background
                />
            </div>
        </el-card>

        <!-- 新增 / 编辑 -->
        <el-dialog v-model="dlg.visible" :title="dlg.edit ? '编辑规则' : '新增规则'" width="620px">
            <el-form label-width="96px" size="small">
                <el-form-item v-if="!dlg.edit" label="匹配位置">
                    <el-select v-model="dlg.target" style="width: 100%" @change="onTargetChange">
                        <el-option v-for="t in targets" :key="t.key" :label="t.label" :value="t.key" />
                    </el-select>
                </el-form-item>
                <el-form-item v-else label="来源">
                    <span class="mono">{{ dlg.file }}.json · {{ dlg.type || '无类型' }}</span>
                </el-form-item>
                <el-form-item label="名称">
                    <el-input v-model="dlg.name" placeholder="便于识别，可留空" />
                </el-form-item>
                <el-form-item label="匹配内容">
                    <el-input
                        v-model="dlg.rule"
                        :type="dlg.file === 'args' || dlg.file === 'header' ? 'textarea' : 'text'"
                        :rows="3"
                        spellcheck="false"
                    />
                </el-form-item>
                <el-form-item label="状态">
                    <el-switch v-model="dlg.state" active-text="启用" inactive-text="停用" />
                </el-form-item>
            </el-form>
            <div class="dlg-tip">{{ dlgTip }}</div>

            <el-alert
                v-if="dlg.preset"
                type="info"
                :closable="false"
                show-icon
                class="preset"
                :title="`将写入 ${dlg.file}.json，type=${dlg.type}`"
            />
            <template #footer>
                <el-button size="small" @click="dlg.visible = false">取消</el-button>
                <el-button size="small" type="primary" :loading="saving" @click="submit">
                    {{ dlg.edit ? '保存并生效' : '新增并生效' }}
                </el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { getWafRuleAll, getWafRuleMeta, opWafRule } from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

type Target = { key: string; label: string; file: string; type: string; tip: string };

const loading = ref(false);
const saving = ref(false);
const files = ref<any[]>([]);
const targets = ref<Target[]>([]);
const rows = ref<any[]>([]);
const page = ref(1);
const pageSize = 24;
const filter = reactive({ file: '', kw: '', onlyOn: false });

const dlg = reactive<any>({
    visible: false,
    edit: false,
    target: 'url',
    file: 'urlBlack',
    type: 'dirFilter',
    name: '',
    rule: '',
    state: true,
    index: -1,
    preset: false,
});

const rowKey = (r: any) => `${r.file}#${r.index}`;

const total = computed(() => rows.value.length);
const pageRows = computed(() => {
    const start = (page.value - 1) * pageSize;
    return rows.value.slice(start, start + pageSize);
});
const dlgTip = computed(() => {
    const t = targets.value.find((x) => x.key === dlg.target);
    if (dlg.edit) return '修改后立即写入对应规则文件并重载 OpenResty。';
    return t ? t.tip : '';
});

const loadMeta = async () => {
    try {
        const d = unwrap(await getWafRuleMeta());
        files.value = d.files || [];
        targets.value = d.targets || [];
        if (!dlg.target && targets.value.length) dlg.target = targets.value[0].key;
    } catch (e: any) {
        ElMessage.error('读取规则库失败：' + (e?.message || e));
    }
};

const loadRules = async () => {
    loading.value = true;
    try {
        const params: any = {};
        if (filter.file) params.file = filter.file;
        if (filter.kw) params.kw = filter.kw;
        if (filter.onlyOn) params.onlyOn = '1';
        const d = unwrap(await getWafRuleAll(params));
        rows.value = d.items || [];
        page.value = 1;
    } catch (e: any) {
        rows.value = [];
        ElMessage.error('读取规则失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const loadAll = async () => {
    await Promise.all([loadMeta(), loadRules()]);
};

const onTargetChange = (key: string) => {
    const t = targets.value.find((x) => x.key === key);
    if (t) {
        dlg.file = t.file;
        dlg.type = t.type;
    }
};

const openCreate = () => {
    if (!targets.value.length) {
        ElMessage.warning('规则库元数据还没加载完');
        return;
    }
    dlg.edit = false;
    dlg.preset = true;
    dlg.name = '';
    dlg.rule = '';
    dlg.state = true;
    dlg.index = -1;
    onTargetChange(dlg.target || targets.value[0].key);
    dlg.visible = true;
};

const openEdit = (row: any) => {
    dlg.edit = true;
    dlg.preset = false;
    dlg.file = row.file;
    dlg.type = row.type;
    dlg.name = row.name || '';
    dlg.rule = row.rule || '';
    dlg.state = row.state !== 'off';
    dlg.index = row.index;
    dlg.visible = true;
};

const submit = async () => {
    if (!dlg.rule.trim()) {
        ElMessage.warning('匹配内容不能为空');
        return;
    }
    saving.value = true;
    try {
        const body: any = {
            op: dlg.edit ? 'update' : 'create',
            file: dlg.file,
            index: dlg.index,
            state: dlg.state ? 'on' : 'off',
            name: dlg.name,
            rule: dlg.rule,
            type: dlg.type,
            reload: true,
        };
        const d = unwrap(await opWafRule(body));
        if (d.reloaded) ElMessage.success(dlg.edit ? '已保存并生效' : '已新增并生效');
        else ElMessage.warning('已写入文件，但重载 OpenResty 失败');
        dlg.visible = false;
        await loadAll();
    } catch (e: any) {
        ElMessage.error('操作失败：' + (e?.message || e));
    } finally {
        saving.value = false;
    }
};

const toggle = async (row: any, v: any) => {
    try {
        const d = unwrap(
            await opWafRule({
                op: 'update',
                file: row.file,
                index: row.index,
                state: v ? 'on' : 'off',
                reload: true,
            }),
        );
        row.state = v ? 'on' : 'off';
        if (!d.reloaded) ElMessage.warning('状态已写入，但重载 OpenResty 失败');
        await loadMeta();
    } catch (e: any) {
        ElMessage.error('切换失败：' + (e?.message || e));
    }
};

const remove = async (row: any) => {
    await ElMessageBox.confirm(
        `确定删除「${row.name || row.rule}」？该操作会直接改写 ${row.file}.json。`,
        '删除规则',
        { type: 'warning' },
    );
    try {
        const d = unwrap(await opWafRule({ op: 'delete', file: row.file, index: row.index, reload: true }));
        if (d.reloaded) ElMessage.success('已删除并生效');
        else ElMessage.warning('已删除，但重载 OpenResty 失败');
        await loadAll();
    } catch (e: any) {
        ElMessage.error('删除失败：' + (e?.message || e));
    }
};

onMounted(async () => {
    // 支持从「全局设置」带 file 参数直接定位到某个规则文件
    const q = String(useRoute().query.file || '').replace(/\.json$/, '');
    if (q) filter.file = q;
    await loadAll();
});
</script>

<style scoped lang="scss">
.card-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    .title {
        font-size: 15px;
        font-weight: 600;
        margin-right: 8px;
    }
    .sub {
        color: var(--el-text-color-secondary);
        font-size: 12px;
    }
    .ops {
        display: flex;
        gap: 8px;
        flex-shrink: 0;
    }
}
.filter-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    .count {
        margin-left: auto;
        font-size: 12px;
        color: var(--el-text-color-secondary);
    }
}
.mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.rule-text {
    font-size: 12px;
    word-break: break-all;
}
.src {
    font-size: 13px;
}
.src-file {
    font-size: 11px;
    color: var(--el-text-color-secondary);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.tip {
    color: var(--el-text-color-secondary);
}
.pager {
    display: flex;
    justify-content: flex-end;
    margin-top: 10px;
}
.dlg-tip {
    font-size: 12px;
    color: var(--el-text-color-secondary);
    margin: 0 0 8px 96px;
    line-height: 1.6;
}
.preset {
    margin-left: 96px;
}
</style>
