<template>
    <div class="rule-inline">
        <div class="ri-toolbar">
            <div class="ri-hint">
                <template v-if="count">{{ count }} 条规则，已启用 {{ enabled }} 条</template>
                <template v-else>暂无规则</template>
                <span v-if="scope === 'site'" class="ri-scope">· 仅作用于当前网站</span>
                <span v-else class="ri-scope">· 仅作为新建网站的默认值</span>
            </div>
            <div class="ri-ops">
                <el-switch
                    v-model="onlyMine"
                    size="small"
                    active-text="只看自定义"
                    inline-prompt
                    style="margin-right: 6px"
                />
                <el-button size="small" :loading="loading" @click="loadAll">刷新</el-button>
                <el-button size="small" type="primary" @click="openCreate">创建规则</el-button>
            </div>
        </div>

        <el-table v-loading="loading" :data="viewRows" size="small" stripe :row-key="rowKey" max-height="420">
            <el-table-column label="匹配对象" width="112">
                <template #default="{ row }">
                    <el-tag size="small" type="info">{{ fileLabel(row.file) }}</el-tag>
                </template>
            </el-table-column>
            <el-table-column label="动作" width="76">
                <template #default="{ row }">
                    <el-tag size="small" :type="actionOf(row.file) === '允许' ? 'success' : 'danger'" effect="plain">
                        {{ actionOf(row.file) }}
                    </el-tag>
                </template>
            </el-table-column>
            <el-table-column label="匹配内容" min-width="230">
                <template #default="{ row }">
                    <span class="mono rule-text">{{ row.rule || '-' }}</span>
                    <div v-if="row.type" class="sub-type">type={{ row.type }}</div>
                </template>
            </el-table-column>
            <el-table-column label="备注" width="150" show-overflow-tooltip>
                <template #default="{ row }">
                    <span>{{ row.name || '-' }}</span>
                </template>
            </el-table-column>
            <el-table-column label="状态" width="80" align="center">
                <template #default="{ row }">
                    <el-switch :model-value="row.state === 'on'" size="small" @change="(v) => toggle(row, v)" />
                </template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
                <template #default="{ row }">
                    <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
                    <el-button link type="danger" @click="remove(row)">删除</el-button>
                </template>
            </el-table-column>
            <template #empty>
                <div class="ri-empty">还没有规则，点右上角「创建规则」新增一条</div>
            </template>
        </el-table>

        <!-- 创建规则：官方同款表单（匹配对象 / 匹配条件 / 匹配内容 / 动作 / 返回状态码） -->
        <el-dialog v-model="cdlg.visible" title="创建规则" width="640px" append-to-body :close-on-click-modal="false">
            <el-form label-width="96px" size="default">
                <el-form-item label="匹配对象">
                    <el-select v-model="cdlg.object" class="w-full" @change="onObjectChange">
                        <el-option v-for="o in usableObjects" :key="o.key" :label="o.label" :value="o.key" />
                    </el-select>
                    <div class="frm-tip">{{ curObject?.tip }}</div>
                </el-form-item>

                <el-form-item label="匹配条件">
                    <el-select v-model="cdlg.cond" class="w-full" :disabled="condLocked">
                        <el-option v-for="c in condOptions" :key="c.key" :label="c.label" :value="c.key" />
                    </el-select>
                    <div v-if="condLocked" class="frm-tip">{{ condLockTip }}</div>
                </el-form-item>

                <el-form-item label="匹配内容">
                    <div class="val-list">
                        <div v-for="(v, i) in cdlg.values" :key="i" class="val-row">
                            <el-input
                                v-model="cdlg.values[i]"
                                :placeholder="valuePlaceholder"
                                spellcheck="false"
                                class="mono"
                            />
                            <el-button link type="danger" :disabled="cdlg.values.length <= 1" @click="removeValue(i)">
                                删除
                            </el-button>
                        </div>
                        <el-button size="small" @click="cdlg.values.push('')">+ 添加</el-button>
                    </div>
                </el-form-item>

                <el-form-item label="动作">
                    <el-radio-group v-model="cdlg.action" @change="onObjectChange">
                        <el-radio-button value="deny" :disabled="!curObject?.deny">禁止</el-radio-button>
                        <el-radio-button value="allow" :disabled="!curObject?.allow">允许</el-radio-button>
                    </el-radio-group>
                    <div class="frm-tip">{{ actionTip }}</div>
                </el-form-item>

                <el-form-item label="返回状态码">
                    <el-select v-model="cdlg.code" class="w-full" :disabled="scope !== 'site'">
                        <el-option label="不修改（沿用模块设置）" :value="0" />
                        <el-option v-for="c in CODE_OPTS" :key="c" :label="codeLabel(c)" :value="c" />
                    </el-select>
                    <div class="frm-tip">
                        {{ scope === 'site'
                            ? '状态码是「模块级」的：该模块下所有规则命中都按这个码返回。444 = 直接断开连接。'
                            : '角色：返回状态码只对站点生效；全局规则请在站点详情里设置' }}
                    </div>
                </el-form-item>

                <el-form-item label="备注">
                    <el-input v-model="cdlg.name" placeholder="便于识别，可留空" maxlength="60" />
                </el-form-item>
                <el-form-item label="状态">
                    <el-switch v-model="cdlg.state" active-text="启用" inactive-text="停用" />
                </el-form-item>
            </el-form>

            <div class="preview">
                <div class="preview-head">
                    <b>生效预览</b>
                    <el-button size="small" link type="primary" :loading="previewing" @click="doPreview">重新计算</el-button>
                </div>
                <div v-if="preview.rows?.length" class="preview-body">
                    <div class="preview-meta">
                        写入 <code>{{ preview.file }}</code>（type={{ preview.type }}），共 {{ preview.count }} 条
                    </div>
                    <div v-for="(r, i) in preview.rows" :key="i" class="preview-row mono">
                        {{ r.rule }}
                    </div>
                </div>
                <div v-else class="preview-meta">{{ preview.msg || '填写内容后自动预览' }}</div>
            </div>
            <el-alert v-if="preview.warnings?.length" type="warning" :closable="false" class="mt-1">
                <template #title>
                    <div v-for="(w, i) in preview.warnings" :key="i">{{ w }}</div>
                </template>
            </el-alert>

            <template #footer>
                <el-button @click="cdlg.visible = false">取消</el-button>
                <el-button type="primary" :loading="saving" @click="submitCreate">创建并生效</el-button>
            </template>
        </el-dialog>

        <!-- 编辑：直接改原始规则内容 -->
        <el-dialog v-model="dlg.visible" title="编辑规则" width="600px" append-to-body>
            <el-form label-width="92px" size="default">
                <el-form-item label="匹配位置">
                    <span>{{ fileLabel(dlg.file) }}</span>
                </el-form-item>
                <el-form-item label="规则内容">
                    <el-input v-model="dlg.rule" type="textarea" :rows="3" spellcheck="false" class="mono" />
                </el-form-item>
                <el-form-item label="备注">
                    <el-input v-model="dlg.name" placeholder="便于识别，可留空" maxlength="60" />
                </el-form-item>
                <el-form-item label="状态">
                    <el-switch v-model="dlg.state" active-text="启用" inactive-text="停用" />
                </el-form-item>
            </el-form>
            <el-alert type="info" :closable="false" title="保存后立即写入规则文件并重载 OpenResty。" />
            <template #footer>
                <el-button @click="dlg.visible = false">取消</el-button>
                <el-button type="primary" :loading="saving" @click="submitEdit">保存并生效</el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { compileWafRule, getWafRuleAll, getWafRuleMeta, opWafRule } from '@/api/modules/waf-log';

type Target = { key: string; label: string; file: string; type: string; tip: string };

const props = withDefaults(
    defineProps<{
        scope?: 'global' | 'site';
        siteKey?: string;
        files?: string[];
        targets?: string[];
        reload?: boolean;
        onlyCustom?: boolean;
    }>(),
    { scope: 'global', siteKey: '', files: () => [], targets: () => [], reload: true, onlyCustom: false },
);

const emit = defineEmits<{ (e: 'changed'): void }>();

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const loading = ref(false);
const saving = ref(false);
const previewing = ref(false);
const rows = ref<any[]>([]);
const allTargets = ref<Target[]>([]);
const onlyMine = ref(false);

const CODE_OPTS = [400, 403, 404, 444, 500, 503, 504];
const codeLabel = (c: number) => (c === 444 ? '444（断开连接）' : String(c));

// 匹配对象 → 规则文件（global / site 两套名字）
type ObjDef = {
    key: string;
    label: string;
    files: string[];
    deny: boolean;
    allow: boolean;
    noRegex?: boolean;
    tip: string;
};
const OBJECTS: ObjDef[] = [
    {
        key: 'url',
        label: 'URL',
        files: ['urlBlack', 'urlWhite', 'defaultUrlBlack'],
        deny: true,
        allow: true,
        tip: '匹配请求 URI，如 /admin、\\.php$',
    },
    {
        key: 'ua',
        label: 'User-Agent',
        files: ['uaBlack', 'uaWhite', 'defaultUaBlack'],
        deny: true,
        allow: true,
        tip: '匹配 User-Agent，如 sqlmap、python-requests',
    },
    {
        key: 'header',
        label: 'Header 值',
        files: ['header'],
        deny: true,
        allow: false,
        tip: '1pwaf 只能按请求头的「值」匹配，不能按名称',
    },
    {
        key: 'cookie',
        label: 'Cookie',
        files: ['cookie'],
        deny: true,
        allow: false,
        tip: '匹配 Cookie 原文',
    },
    {
        key: 'args',
        label: '请求参数',
        files: ['args'],
        deny: true,
        allow: false,
        tip: '匹配参数里的攻击特征串',
    },
    {
        key: 'method',
        label: '请求方法',
        files: ['methodWhite'],
        deny: false,
        allow: true,
        tip: 'methodWhite 是「允许的方法」列表，只能配「允许」动作',
    },
    {
        key: 'ip',
        label: '来源 IP',
        files: ['ipBlack', 'ipWhite'],
        deny: true,
        allow: true,
        noRegex: true,
        tip: '支持单 IP、CIDR（1.2.3.0/24）、区间（1.2.3.1-1.2.3.9）',
    },
    {
        key: 'fileExt',
        label: '文件后缀',
        files: ['fileExt'],
        deny: true,
        allow: false,
        noRegex: true,
        tip: '只写后缀名，如 bak、sql；仅对上传体生效',
    },
];

const CONDS = [
    { key: 'eq', label: '等于' },
    { key: 'ne', label: '不等于' },
    { key: 'contain', label: '包含' },
    { key: 'notContain', label: '不包含' },
    { key: 'regex', label: '正则匹配' },
];

const dlg = reactive<any>({ visible: false, file: '', type: '', rule: '', name: '', state: true, index: -1 });
const cdlg = reactive<any>({
    visible: false,
    object: 'url',
    cond: 'contain',
    values: [''],
    action: 'deny',
    code: 0,
    name: '',
    state: true,
});
const preview = reactive<any>({ rows: [], file: '', type: '', count: 0, warnings: [], msg: '' });

const rowKey = (r: any) => `${r.file}#${r.index}`;
const query = computed(() => (props.scope === 'site' && props.siteKey ? { key: props.siteKey } : {}));
const fileAllowed = (f: string) => !props.files.length || props.files.includes(f);

const usableObjects = computed(() => OBJECTS.filter((o) => o.files.some((f) => fileAllowed(f))));
const curObject = computed(() => OBJECTS.find((o) => o.key === cdlg.object));
const condLocked = computed(() => !!curObject.value?.noRegex);
const condLockTip = computed(() => {
    if (cdlg.object === 'ip') return 'IP 只支持「属于 / 不属于 IP 组」，直接填 IP 段即可';
    if (cdlg.object === 'method') return '请求方法只能精确匹配';
    if (cdlg.object === 'fileExt') return '文件后缀只能精确匹配';
    return '';
});
const condOptions = computed(() => {
    if (curObject.value?.noRegex) {
        if (cdlg.object === 'ip') return [{ key: 'inGroup', label: '属于 IP 组' }];
        return [{ key: 'eq', label: '精确匹配' }];
    }
    // 「不等于」只有 URL 能可靠翻译（1pwaf 对其它对象会误拦），其余对象隐藏
    return cdlg.object === 'url' ? CONDS : CONDS.filter((c) => c.key !== 'ne');
});
const valuePlaceholder = computed(() => {
    switch (cdlg.object) {
        case 'ip':
            return '1.2.3.4 / 1.2.3.0/24 / 1.2.3.1-1.2.3.9';
        case 'method':
            return 'TRACE';
        case 'fileExt':
            return 'bak';
        case 'header':
            return '请求头的值，如 ac lprobe（不是「名称: 值」）';
        default:
            return '要匹配的内容，一行一条';
    }
});
const actionTip = computed(() => {
    if (cdlg.object === 'method') return 'methodWhite 只维护白名单：勾「允许」表示把该方法加入放行列表';
    if (!curObject.value?.deny) return '1pwaf 没有该对象的「禁止」规则文件';
    if (!curObject.value?.allow) return '1pwaf 没有该对象的「允许」规则文件，只能用「禁止」';
    return '';
});

const isBuiltin = (r: any) => /^\d{6}$/.test(String(r.name || ''));
const viewRows = computed(() => (onlyMine.value ? rows.value.filter((r) => !isBuiltin(r)) : rows.value));
const count = computed(() => viewRows.value.length);
const enabled = computed(() => viewRows.value.filter((r) => r.state === 'on').length);

const actionOf = (file: string) => (/(White)$/.test(file) || file === 'methodWhite' ? '允许' : '禁止');

const fileLabel = (file: string) => {
    const hit = allTargets.value.find((t) => t.file === file);
    if (hit) return hit.label;
    const map: Record<string, string> = {
        defaultUrlBlack: 'URL',
        defaultUaBlack: 'User-Agent',
        header: 'Header 值',
        cookie: 'Cookie',
        args: '请求参数',
        fileExt: '文件后缀',
        methodWhite: '请求方法',
        urlBlack: 'URL',
        urlWhite: 'URL',
        uaBlack: 'User-Agent',
        uaWhite: 'User-Agent',
        ipBlack: '来源 IP',
        ipWhite: '来源 IP',
    };
    return map[file] || file;
};

const loadAll = async () => {
    if (props.scope === 'site' && !props.siteKey) return;
    loading.value = true;
    try {
        const meta = unwrap(await getWafRuleMeta(query.value));
        allTargets.value = meta.targets || [];
        const all = unwrap(await getWafRuleAll(query.value));
        let list = (all.items || []).filter((r: any) => fileAllowed(r.file));
        if (props.onlyCustom && props.scope === 'site') {
            const g = unwrap(await getWafRuleAll({}));
            const sig = (r: any) => `${r.file}|${r.rule}|${r.type || ''}`;
            const builtin = new Set((g.items || []).map(sig));
            list = list.filter((r: any) => !builtin.has(sig(r)));
        }
        rows.value = list;
    } catch (e: any) {
        rows.value = [];
        ElMessage.error('读取规则失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const onObjectChange = () => {
    const o = curObject.value;
    if (!o) return;
    if (o.noRegex) cdlg.cond = o.key === 'ip' ? 'inGroup' : 'eq';
    else if (!condOptions.value.some((c) => c.key === cdlg.cond)) cdlg.cond = 'contain';
    if (!o.deny && cdlg.action === 'deny') cdlg.action = 'allow';
    if (!o.allow && cdlg.action === 'allow') cdlg.action = 'deny';
    doPreview();
};

const removeValue = (i: number) => {
    cdlg.values.splice(i, 1);
    if (!cdlg.values.length) cdlg.values.push('');
    doPreview();
};

let previewTimer: any = null;
const schedulePreview = () => {
    if (previewTimer) clearTimeout(previewTimer);
    previewTimer = setTimeout(() => doPreview(), 350);
};

const doPreview = async () => {
    if (!cdlg.visible) return;
    const vals = cdlg.values.map((v: string) => String(v || '').trim()).filter(Boolean);
    if (!vals.length) {
        preview.rows = [];
        preview.msg = '填写匹配内容后自动预览';
        return;
    }
    previewing.value = true;
    try {
        const d = unwrap(
            await compileWafRule({
                key: props.scope === 'site' ? props.siteKey : '',
                object: cdlg.object,
                cond: cdlg.cond,
                values: vals,
                action: cdlg.action,
                preview: true,
            }),
        );
        preview.rows = d.rows || [];
        preview.file = d.file;
        preview.type = d.type;
        preview.count = d.count;
        preview.warnings = d.warnings || [];
        preview.msg = '';
    } catch (e: any) {
        preview.rows = [];
        preview.warnings = [];
        preview.msg = e?.message || '预览失败';
    } finally {
        previewing.value = false;
    }
};

watch(
    () => [cdlg.object, cdlg.cond, cdlg.action, cdlg.values.join('\u0001')],
    () => schedulePreview(),
);

const openCreate = () => {
    const first = usableObjects.value[0];
    if (!first) {
        ElMessage.warning('当前页面没有可创建的规则类型');
        return;
    }
    cdlg.object = first.key;
    cdlg.action = first.deny ? 'deny' : 'allow';
    cdlg.cond = first.noRegex ? (first.key === 'ip' ? 'inGroup' : 'eq') : 'contain';
    cdlg.values = [''];
    cdlg.code = 0;
    cdlg.name = '';
    cdlg.state = true;
    preview.rows = [];
    preview.warnings = [];
    preview.msg = '';
    cdlg.visible = true;
};

const submitCreate = async () => {
    const vals = cdlg.values.map((v: string) => String(v || '').trim()).filter(Boolean);
    if (!vals.length) {
        ElMessage.warning('匹配内容不能为空');
        return;
    }
    saving.value = true;
    try {
        const body: any = {
            key: props.scope === 'site' ? props.siteKey : '',
            object: cdlg.object,
            cond: cdlg.cond,
            values: vals,
            action: cdlg.action,
            name: cdlg.name,
            state: cdlg.state ? 'on' : 'off',
            code: cdlg.code,
            reload: props.reload,
            preview: false,
        };
        const d = unwrap(await compileWafRule(body));
        const w = (d.warnings || []).join('；');
        if (d.reloaded === false) ElMessage.warning('已写入，但重载 OpenResty 失败');
        else ElMessage.success(`已创建 ${d.added} 条规则并生效${w ? '，注意：' + w : ''}`);
        cdlg.visible = false;
        await loadAll();
        emit('changed');
    } catch (e: any) {
        ElMessage.error('创建失败：' + (e?.message || e));
    } finally {
        saving.value = false;
    }
};

const openEdit = (row: any) => {
    dlg.visible = true;
    dlg.file = row.file;
    dlg.type = row.type || '';
    dlg.rule = row.rule || '';
    dlg.name = row.name || '';
    dlg.state = row.state !== 'off';
    dlg.index = row.index;
};

const submitEdit = async () => {
    if (!String(dlg.rule).trim()) {
        ElMessage.warning('规则内容不能为空');
        return;
    }
    saving.value = true;
    try {
        const body: any = {
            op: 'update',
            file: dlg.file,
            index: dlg.index,
            state: dlg.state ? 'on' : 'off',
            name: dlg.name,
            rule: dlg.rule,
            type: dlg.type,
            reload: props.reload,
        };
        if (props.scope === 'site') body.key = props.siteKey;
        const d = unwrap(await opWafRule(body));
        if (d.reloaded === false) ElMessage.warning('已写入，但重载 OpenResty 失败');
        else ElMessage.success('已保存并生效');
        dlg.visible = false;
        await loadAll();
        emit('changed');
    } catch (e: any) {
        ElMessage.error('操作失败：' + (e?.message || e));
    } finally {
        saving.value = false;
    }
};

const toggle = async (row: any, v: any) => {
    try {
        const body: any = {
            op: 'update',
            file: row.file,
            index: row.index,
            state: v ? 'on' : 'off',
            reload: props.reload,
        };
        if (props.scope === 'site') body.key = props.siteKey;
        const d = unwrap(await opWafRule(body));
        row.state = v ? 'on' : 'off';
        if (d.reloaded === false) ElMessage.warning('状态已写入，但重载失败');
        emit('changed');
    } catch (e: any) {
        ElMessage.error('切换失败：' + (e?.message || e));
        await loadAll();
    }
};

const remove = async (row: any) => {
    try {
        await ElMessageBox.confirm(`确定删除「${row.name || row.rule}」？删除后立即生效。`, '删除规则', {
            type: 'warning',
            confirmButtonText: '删除',
            cancelButtonText: '取消',
        });
    } catch {
        return;
    }
    try {
        const body: any = { op: 'delete', file: row.file, index: row.index, reload: props.reload };
        if (props.scope === 'site') body.key = props.siteKey;
        const d = unwrap(await opWafRule(body));
        if (d.reloaded === false) ElMessage.warning('已删除，但重载失败');
        else ElMessage.success('已删除');
        await loadAll();
        emit('changed');
    } catch (e: any) {
        ElMessage.error('删除失败：' + (e?.message || e));
    }
};

watch(() => props.siteKey, () => loadAll());
onMounted(loadAll);
</script>

<style scoped>
.rule-inline {
    width: 100%;
}
.ri-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 8px;
}
.ri-hint {
    color: var(--el-text-color-secondary);
    font-size: 13px;
}
.ri-scope {
    color: var(--el-text-color-placeholder);
    margin-left: 4px;
}
.ri-ops {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
}
.mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.rule-text {
    font-size: 12px;
    word-break: break-all;
}
.sub-type {
    color: var(--el-text-color-placeholder);
    font-size: 11px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.ri-empty {
    color: var(--el-text-color-placeholder);
    font-size: 13px;
    padding: 12px 0;
}
.w-full {
    width: 100%;
}
.frm-tip {
    margin-top: 2px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
    line-height: 1.5;
}
.val-list {
    width: 100%;
}
.val-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
}
.preview {
    margin-top: 4px;
    padding: 10px 12px;
    border-radius: 6px;
    background: var(--el-fill-color-light);
}
.preview-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
    font-size: 13px;
}
.preview-meta {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    line-height: 1.7;
}
.preview-row {
    font-size: 12px;
    word-break: break-all;
    line-height: 1.7;
    color: var(--el-text-color-regular);
}
.mt-1 {
    margin-top: 8px;
}
</style>
