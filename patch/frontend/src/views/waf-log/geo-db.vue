<template>
    <div v-loading="loading">
        <ConfigCard
            header="IP 库"
            description="BlackIP / SpiderIP / GeoIP 三个 mmdb。可从当前 openresty 镜像直接提取内置库，也可填入自定义地址覆盖；下载到 MaxMind 原始结构会自动转换。所有操作自动备份，可一键还原"
        >
            <template #content-form>
                <el-table :data="items" size="small" border class="ipdb-table">
                    <el-table-column prop="name" label="库" width="96">
                        <template #default="{ row }">
                            <b>{{ row.name }}</b>
                        </template>
                    </el-table-column>
                    <el-table-column label="状态" width="150">
                        <template #default="{ row }">
                            <template v-if="row.exists">
                                <el-tag :type="row.valid ? 'success' : 'danger'" effect="light" size="small">
                                    {{ row.valid ? '有效' : '异常' }}
                                </el-tag>
                                <span class="ipdb-meta">{{ fmtSize(row.size) }}</span>
                            </template>
                            <el-tag v-else type="info" effect="light" size="small">缺失</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="结构" min-width="180">
                        <template #default="{ row }">
                            <el-tag v-if="row.schema" size="small" effect="plain" :type="schemaType(row)">
                                {{ row.schema_label || row.schema }}
                            </el-tag>
                            <span v-if="row.build_epoch" class="ipdb-meta">数据日期 {{ row.build_epoch }}</span>
                            <div v-if="row.reason" class="ipdb-err">{{ row.reason }}</div>
                            <div v-else-if="row.note" class="ipdb-meta">{{ row.note }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="desc" label="用途" min-width="180" show-overflow-tooltip />
                    <el-table-column label="更新时间" width="150">
                        <template #default="{ row }">{{ row.mtime || '-' }}</template>
                    </el-table-column>
                    <el-table-column label="sha256" min-width="150">
                        <template #default="{ row }">
                            <span v-if="row.sha256" class="ipdb-sha" :title="row.sha256" @click="copy(row.sha256)">
                                {{ row.sha256.slice(0, 12) }}…
                            </span>
                            <span v-else class="ipdb-meta">-</span>
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="230">
                        <template #default="{ row }">
                            <el-button link type="primary" :loading="busy === row.name + ':extract'" @click="extract(row)">
                                镜像提取
                            </el-button>
                            <el-button link type="primary" @click="openUrl(row)">自定义地址</el-button>
                            <el-button link :disabled="!row.backups" @click="restore(row)">还原</el-button>
                        </template>
                    </el-table-column>
                </el-table>

                <div class="ipdb-foot">
                    <span class="ipdb-hint">
                        目录：{{ dir || '未检测到' }}<span v-if="image">；镜像：{{ image }}</span>
                    </span>
                    <el-button link type="primary" @click="load">刷新</el-button>
                </div>

                <el-alert type="info" :closable="false" class="mt-1">
                    <template #title>
                        官方商业版的「更新 IP 组 / 蜘蛛 IP 池 / IP 地址库」走 xpack 私有下载地址，社区版无法调用，这里用镜像内置库与自定义地址替代。
                        GeoIP 需要 <b>顶层 province</b> 的扁平结构；直接给 MaxMind 的 GeoLite2-City（嵌套结构）会被自动转换，
                        转换后省份字段来自 <code>subdivisions[0]</code>，个别网段可能没有省份（Geo 数据精度差异）。
                    </template>
                </el-alert>
                <div v-if="attribution" class="ipdb-attr">{{ attribution }}</div>
            </template>
        </ConfigCard>

        <el-dialog v-model="dlg" :title="`自定义地址 - ${cur?.name || ''}`" width="680px" :close-on-click-modal="false">
            <el-input v-model="urlInput" placeholder="https://example.com/GeoLite2-City.mmdb 或 .mmdb.tar.gz" clearable />
            <div class="preset-row">
                <span class="preset-label">常用来源：</span>
                <el-button
                    v-for="p in presets(cur?.name)"
                    :key="p.url"
                    size="small"
                    link
                    type="primary"
                    @click="urlInput = p.url"
                >
                    {{ p.label }}
                </el-button>
            </div>
            <div class="mirror-row">
                <el-checkbox v-model="useMirror">使用加速源下载</el-checkbox>
                <el-select v-model="mirrorPreset" size="small" :disabled="!useMirror" style="width: 230px">
                    <el-option v-for="m in mirrorOptions" :key="m.value" :label="m.label" :value="m.value" />
                    <el-option label="自定义加速镜像…" value="custom" />
                </el-select>
                <el-input
                    v-if="useMirror && mirrorPreset === 'custom'"
                    v-model="customMirror"
                    size="small"
                    clearable
                    placeholder="https://xxx/ 或 https://xxx/fetch?u={url}"
                    style="margin-top: 6px"
                />
                <span class="ipdb-meta" style="margin-left: 8px">
                    默认直连优先、失败自动回退；勾选后优先走所选镜像（推荐 v4.gh-proxy.org）
                </span>
            </div>
            <el-checkbox v-model="autoConvert" :disabled="cur?.name !== 'GeoIP'" class="mt-1">
                自动转换 MaxMind 结构（GeoLite2 → 1pwaf 扁平结构）
            </el-checkbox>
            <div class="dlg-tip">
                支持 <code>.mmdb</code> / <code>.mmdb.gz</code> / <code>.tar.gz</code> / <code>.zip</code>；
                下载后先校验再替换，失败不会覆盖现有文件。转换 1600 万网段大约需要 6~10 分钟，进度会实时显示。
            </div>

            <div v-if="job.state === 'running'" class="job-box">
                <div class="job-head">
                    <b>{{ job.phase }}</b>
                    <span class="ipdb-meta">{{ job.pct }}% · 已用 {{ job.elapsed }}s</span>
                </div>
                <el-progress :percentage="job.pct" :stroke-width="10" :show-text="false" />
                <div class="job-msg">{{ job.msg }}</div>
            </div>
            <el-alert v-if="job.state === 'error'" type="error" :closable="false" class="mt-1" :title="job.err" />

            <template #footer>
                <el-button :disabled="job.state === 'running'" @click="dlg = false">关闭</el-button>
                <el-button type="primary" :loading="job.state === 'running'" :disabled="job.state === 'running'" @click="applyUrl">
                    下载并应用
                </el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import ConfigCard from '@/components/config-card/index.vue';
import {
    extractWafGeoDb,
    fromUrlWafGeoDb,
    getWafGeoDb,
    getWafGeoDbJob,
    restoreWafGeoDb,
} from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const loading = ref(false);
const busy = ref('');
const items = ref<any[]>([]);
const dir = ref('');
const image = ref('');
const attribution = ref('');
const dlg = ref(false);
const cur = ref<any>(null);
const urlInput = ref('');
const autoConvert = ref(true);
const useMirror = ref(false);
const mirrorPreset = ref('https://v4.gh-proxy.org/');
const customMirror = ref('');
const mirrorOptions = [
    { label: 'v4.gh-proxy.org（推荐）', value: 'https://v4.gh-proxy.org/' },
    { label: 'gh-proxy.com', value: 'https://gh-proxy.com/' },
    { label: 'ghfast.top', value: 'https://ghfast.top/' },
    { label: 'ghproxy.net', value: 'https://ghproxy.net/' },
];
const mirrorValue = computed(() => {
    if (!useMirror.value) return '';
    return mirrorPreset.value === 'custom' ? customMirror.value.trim() : mirrorPreset.value;
});
const job = ref<any>({ state: 'idle', pct: 0, phase: '', msg: '', err: '', elapsed: 0 });

let timer: any = null;

const fmtSize = (n: number) => {
    const v = Number(n || 0);
    if (v >= 1 << 20) return `${(v / (1 << 20)).toFixed(1)} MB`;
    if (v >= 1 << 10) return `${(v / (1 << 10)).toFixed(1)} KB`;
    return `${v} B`;
};

const schemaType = (row: any) => {
    if (row.schema === 'flat') return row.has_province ? 'success' : 'warning';
    if (row.schema === 'maxmind') return 'warning';
    if (row.schema === 'iplist') return 'info';
    return 'info';
};

const P3TERX = (name: string) =>
    `https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-${name}.mmdb`;

const presets = (name: string) => {
    if (name !== 'GeoIP') return [];
    return [
        { label: 'P3TERX GeoLite2-City（裸 mmdb）', url: P3TERX('City') },
        { label: 'P3TERX GeoLite2-Country', url: P3TERX('Country') },
    ];
};

const copy = async (txt: string) => {
    try {
        await navigator.clipboard.writeText(txt);
        ElMessage.success('已复制 sha256');
    } catch {
        ElMessage.warning('复制失败，请手动选择');
    }
};

const load = async () => {
    loading.value = true;
    try {
        const d = unwrap(await getWafGeoDb());
        items.value = d.items || [];
        dir.value = d.dir || '';
        image.value = d.image || '';
        attribution.value = d.attribution || '';
    } catch (e: any) {
        ElMessage.error('读取 IP 库信息失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const stopPoll = () => {
    if (timer) {
        clearInterval(timer);
        timer = null;
    }
};

const poll = async (name: string) => {
    try {
        const d = unwrap(await getWafGeoDbJob(name));
        const j = d.job || { state: d.state || 'idle', pct: d.pct || 0, phase: d.phase, msg: d.msg };
        job.value = {
            state: j.state,
            pct: j.pct || 0,
            phase: j.phase || '',
            msg: j.msg || '',
            err: j.err || '',
            elapsed: j.elapsed || Math.round((Date.now() - t0.value) / 1000),
        };
        if (j.state === 'done') {
            stopPoll();
            const r = j.result || {};
            const w = (r.warnings || []).join('；');
            const conv = r.converted ? '（已自动转换为 1pwaf 扁平结构）' : '';
            ElMessage.success(`已更新 ${name}${conv} ${fmtSize(r.size)}${w ? '，注意：' + w : ''}`);
            dlg.value = false;
            await load();
        } else if (j.state === 'error') {
            stopPoll();
        }
    } catch (e: any) {
        stopPoll();
        job.value = { ...job.value, state: 'error', err: e?.message || '查询任务失败' };
    }
};

const t0 = ref(0);

const startPoll = (name: string) => {
    stopPoll();
    t0.value = Date.now();
    timer = setInterval(() => poll(name), 3000);
    poll(name);
};

const extract = async (row: any) => {
    try {
        await ElMessageBox.confirm(
            `将用镜像自带的 ${row.name}.mmdb 覆盖当前文件（会先备份），是否继续？`,
            '镜像提取',
            { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' },
        );
    } catch {
        return;
    }
    busy.value = row.name + ':extract';
    try {
        const d = unwrap(await extractWafGeoDb({ name: row.name, reload: true }));
        ElMessage.success(`已提取 ${row.name}（${fmtSize(d.size)}）`);
        await load();
    } catch (e: any) {
        ElMessage.error(e?.message || '提取失败');
    } finally {
        busy.value = '';
    }
};

const openUrl = (row: any) => {
    cur.value = row;
    urlInput.value = '';
    autoConvert.value = true;
    useMirror.value = false;
    mirrorPreset.value = 'https://v4.gh-proxy.org/';
    customMirror.value = '';
    job.value = { state: 'idle', pct: 0, phase: '', msg: '', err: '', elapsed: 0 };
    dlg.value = true;
};

const applyUrl = async () => {
    const u = urlInput.value.trim();
    if (!u) {
        ElMessage.warning('请填写地址');
        return;
    }
    if (useMirror.value && mirrorPreset.value === 'custom' && !/^https?:\/\//.test(customMirror.value.trim())) {
        ElMessage.warning('自定义加速镜像必须以 http:// 或 https:// 开头');
        return;
    }
    job.value = { state: 'running', pct: 1, phase: '启动', msg: '正在提交任务…', err: '', elapsed: 0 };
    try {
        const d = unwrap(
            await fromUrlWafGeoDb({
                name: cur.value.name,
                url: u,
                reload: true,
                convert: autoConvert.value,
                mirror: mirrorValue.value,
                async: true,
            }),
        );
        if (d.state === 'running') {
            startPoll(cur.value.name);
        } else {
            ElMessage.success('已更新');
            dlg.value = false;
            await load();
        }
    } catch (e: any) {
        job.value = { ...job.value, state: 'error', err: e?.message || '启动失败' };
    }
};

const restore = async (row: any) => {
    try {
        await ElMessageBox.confirm(`用最近一次备份还原 ${row.name}.mmdb？`, '还原备份', {
            confirmButtonText: '确认',
            cancelButtonText: '取消',
            type: 'warning',
        });
    } catch {
        return;
    }
    try {
        await restoreWafGeoDb({ name: row.name });
        ElMessage.success('已还原');
        await load();
    } catch (e: any) {
        ElMessage.error(e?.message || '还原失败');
    }
};

onMounted(async () => {
    await load();
    // 进页面时如果后台还有任务在跑，自动恢复进度显示
    for (const nm of ['GeoIP', 'BlackIP', 'SpiderIP']) {
        const d = unwrap(await getWafGeoDbJob(nm));
        if (d.state === 'running') {
            cur.value = { name: nm };
            dlg.value = true;
            startPoll(nm);
            break;
        }
    }
});

onUnmounted(stopPoll);
</script>

<style scoped>
.ipdb-table {
    width: 100%;
}
.ipdb-meta {
    margin-left: 8px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.mirror-row {
    margin: 10px 0 4px;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
}
.ipdb-err {
    margin-top: 2px;
    color: var(--el-color-danger);
    font-size: 12px;
}
.ipdb-sha {
    font-family: var(--el-font-family-mono, monospace);
    font-size: 12px;
    color: var(--el-text-color-secondary);
    cursor: pointer;
}
.ipdb-sha:hover {
    color: var(--el-color-primary);
    text-decoration: underline;
}
.ipdb-foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 8px;
    gap: 12px;
}
.ipdb-hint,
.ipdb-attr {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    word-break: break-all;
}
.ipdb-attr {
    margin-top: 6px;
}
.mt-1 {
    margin-top: 8px;
}
.dlg-tip {
    margin-top: 6px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.preset-row {
    margin-top: 8px;
    display: flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
}
.preset-label {
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.job-box {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 6px;
    background: var(--el-fill-color-light);
}
.job-head {
    display: flex;
    justify-content: space-between;
    margin-bottom: 6px;
    font-size: 13px;
}
.job-msg {
    margin-top: 6px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
    word-break: break-all;
}
</style>
