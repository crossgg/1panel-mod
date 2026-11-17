<template>
    <LayoutContent title="封锁记录" :divider="true">
        <template #rightToolBar>
            <el-input
                v-model="kw"
                placeholder="请输入 IP"
                clearable
                style="width: 220px"
                @keyup.enter="reload"
                @clear="reload"
            />
            <el-button :loading="loading" @click="reload">刷新</el-button>
            <el-button :disabled="!rows.length" @click="doExport">导出</el-button>
        </template>
        <template #main>
            <el-alert
                type="info"
                :closable="false"
                class="mb-2"
                title="封锁 IP 临时存储在 OpenResty 共享内存中，重启 OpenResty 会全部解封；如需永久封禁请使用「拉黑」，加白后该 IP 将不受任何规则限制"
            />
            <div v-loading="loading">
                <div class="block-toolbar">
                    <el-radio-group v-model="status" class="compact-segment" @change="reload">
                        <el-radio-button value="">全部 {{ info.all }}</el-radio-button>
                        <el-radio-button value="blocking">封禁中 {{ info.blocking }}</el-radio-button>
                        <el-radio-button value="free">已解封</el-radio-button>
                    </el-radio-group>
                    <span class="ml-5 tip">
                        共 {{ info.total }} 条{{ info.hint ? '：' + info.hint : '' }}
                    </span>
                </div>

                <el-table :data="rows" :height="480">
                    <el-table-column label="攻击 IP" prop="ip" min-width="160" show-overflow-tooltip />
                    <el-table-column label="状态" width="120">
                        <template #default="{ row }">
                            <el-tag :type="row.status === 'blocking' ? 'danger' : 'info'" effect="light">
                                {{ row.status === 'blocking' ? '封禁中' : '已解封' }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="封禁时间" prop="create_date" width="180">
                        <template #default="{ row }">{{ localTime(row.create_date) }}</template>
                    </el-table-column>
                    <el-table-column label="到期时间" prop="expire_at" width="180">
                        <template #default="{ row }">{{ row.expire_at || '-' }}</template>
                    </el-table-column>
                    <el-table-column label="剩余" width="120">
                        <template #default="{ row }">
                            <span :class="{ expired: row.remain <= 0 }">{{ remainText(row) }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="210" fixed="right">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="unlock(row)">解封</el-button>
                            <el-button link type="primary" @click="addToList(row, 'black')">拉黑</el-button>
                            <el-button link type="primary" @click="addToList(row, 'white')">加白</el-button>
                        </template>
                    </el-table-column>
                </el-table>

                <div class="pager">
                    <el-pagination
                        v-model:current-page="page"
                        v-model:page-size="size"
                        :total="info.total"
                        :page-sizes="[20, 50, 100]"
                        layout="total, sizes, prev, pager, next"
                        @current-change="load"
                        @size-change="reload"
                    />
                </div>
            </div>
        </template>
    </LayoutContent>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import {
    addWafBlockIp,
    exportWafBlockUrl,
    getWafBlockList,
    removeWafBlock,
} from '@/api/modules/waf-log';

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const loading = ref(false);
const rows = ref<any[]>([]);
const kw = ref('');
const status = ref('');
const page = ref(1);
const size = ref(20);
const info = reactive<any>({ total: 0, blocking: 0, all: 0, hint: '' });

const load = async () => {
    loading.value = true;
    try {
        const d = unwrap(
            await getWafBlockList({ page: page.value, size: size.value, kw: kw.value, status: status.value }),
        );
        rows.value = d.items || [];
        info.total = d.total || 0;
        info.blocking = d.blocking || 0;
        info.all = d.all || 0;
        info.hint = d.hint || '';
    } catch (e: any) {
        rows.value = [];
        ElMessage.error('读取封锁记录失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const reload = () => {
    page.value = 1;
    load();
};

// create_date 是 sqlite 的 UTC 时间，转成本地展示
const localTime = (v: string) => {
    if (!v) return '-';
    const t = new Date(v.replace(' ', 'T') + 'Z');
    if (isNaN(t.getTime())) return v;
    const p = (n: number) => String(n).padStart(2, '0');
    return `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())} ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
};

const remainText = (row: any) => {
    if (row.remain == null) return '-';
    if (row.remain <= 0) return '已到期';
    const s = Number(row.remain);
    if (s >= 3600) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
    if (s >= 60) return `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
    return `${s} 秒`;
};

const unlock = async (row: any) => {
    try {
        await ElMessageBox.confirm(`是否解封 IP：${row.ip}？`, '解封', {
            confirmButtonText: '确认',
            cancelButtonText: '取消',
            type: 'warning',
        });
    } catch {
        return;
    }
    try {
        const d = unwrap(await removeWafBlock({ ids: [row.id] }));
        ElMessage.success(`已移除 ${d.removed || 0} 条封锁记录`);
        await load();
    } catch (e: any) {
        ElMessage.error('解封失败：' + (e?.message || e));
    }
};

const addToList = async (row: any, kind: 'black' | 'white') => {
    const label = kind === 'black' ? '默认黑名单' : '默认白名单';
    try {
        await ElMessageBox.confirm(
            kind === 'black'
                ? `是否把 IP：${row.ip} 添加到默认黑名单?`
                : `是否把 IP：${row.ip} 添加到默认白名单?`,
            kind === 'black' ? '拉黑' : '加白',
            { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' },
        );
    } catch {
        return;
    }
    try {
        const d = unwrap(await addWafBlockIp({ ips: [row.ip], kind }));
        if (d.added) {
            ElMessage.success(`已加入${label}并重载 OpenResty`);
        } else if (d.skipped) {
            ElMessage.info(`已在${label}中，无需重复添加`);
        } else {
            ElMessage.warning((d.failed || []).join('；') || '未写入');
        }
        await load();
    } catch (e: any) {
        ElMessage.error('操作失败：' + (e?.message || e));
    }
};

const doExport = () => {
    window.open(exportWafBlockUrl, '_blank');
};

onMounted(load);
</script>

<style scoped>
.block-toolbar {
    display: flex;
    align-items: center;
    margin-bottom: 12px;
}
.compact-segment {
    white-space: nowrap;
}
.compact-segment :deep(.el-radio-button__inner) {
    padding: 6px 12px;
    border: 1px solid var(--el-border-color);
    border-left-width: 0;
    outline: none;
}
.compact-segment :deep(.el-radio-button:first-child .el-radio-button__inner) {
    border-left-width: 1px;
}
.tip {
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.ml-5 {
    margin-left: 16px;
}
.mb-2 {
    margin-bottom: 8px;
}
.expired {
    color: var(--el-text-color-placeholder);
}
.pager {
    display: flex;
    justify-content: flex-end;
    margin-top: 12px;
}
</style>
