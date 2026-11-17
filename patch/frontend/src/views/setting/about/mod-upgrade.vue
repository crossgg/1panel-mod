<template>
    <div>
        <el-link underline="never" type="primary" class="mod-link" @click="open">Mod 更新</el-link>
        <el-dialog v-model="visible" title="Mod 版更新" width="580px" :close-on-click-modal="false">
            <div class="mod-row">
                <span class="mod-label">当前版本</span>
                <b>{{ info.current || '未安装' }}</b>
                <span class="mod-sub">{{ info.repo }}</span>
            </div>

            <el-button type="primary" plain size="small" :loading="checking" @click="check">检查更新</el-button>

            <template v-if="info.checked">
                <el-alert v-if="info.error" type="warning" :closable="false" show-icon :title="info.error" class="mod-gap" />
                <template v-else>
                    <div class="mod-row mod-gap">
                        <span class="mod-label">最新版本</span>
                        <b>{{ info.latest || '-' }}</b>
                        <el-tag v-if="info.has_update" type="warning" size="small">有新版本</el-tag>
                        <el-tag v-else type="success" size="small">已是最新</el-tag>
                    </div>
                    <div class="mod-sub" v-if="info.published_at">发布时间：{{ info.published_at }}</div>
                    <div class="mod-notes" v-if="info.notes">{{ info.notes }}</div>
                </template>
            </template>

            <el-alert type="info" :closable="false" class="mod-gap" show-icon>
                <template #title>
                    Mod 版不在面板内自动升级。请到仓库 Release 页查看该版本对应的更新命令（下载产物后执行
                    <code>sudo bash install.sh</code>）。
                </template>
            </el-alert>
            <div class="mod-gap">
                <el-link type="primary" :href="info.releases_url" target="_blank" rel="noopener noreferrer">
                    前往 {{ info.repo }} Releases
                </el-link>
            </div>
            <template #footer>
                <el-button @click="visible = false">关闭</el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { getWafModVersion } from '@/api/modules/waf-log';

const visible = ref(false);
const checking = ref(false);
const info = ref<any>({
    repo: 'crossgg/1panel-mod',
    releases_url: 'https://github.com/crossgg/1panel-mod/releases',
    current: '',
    checked: false,
});

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : res || {});

// 打开弹窗时只读本地版本，不发网络请求
const open = async () => {
    visible.value = true;
    try {
        info.value = unwrap(await getWafModVersion({}));
    } catch (e) {
        info.value = { ...info.value, error: '读取本地版本失败，可直接点「检查更新」' };
    }
};

// 只有点这个按钮才真的去查 GitHub
const check = async () => {
    checking.value = true;
    try {
        info.value = unwrap(await getWafModVersion({ check: 1 }));
    } catch (e: any) {
        info.value = { ...info.value, checked: true, error: e?.message || '检查失败' };
    } finally {
        checking.value = false;
    }
};
</script>

<style scoped>
.mod-link {
    margin-left: 12px;
}
.mod-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
}
.mod-label {
    color: var(--el-text-color-secondary);
}
.mod-sub {
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.mod-gap {
    margin-top: 12px;
}
.mod-notes {
    margin-top: 8px;
    padding: 8px 10px;
    max-height: 180px;
    overflow: auto;
    background: var(--el-fill-color-light);
    border-radius: 4px;
    white-space: pre-wrap;
    font-size: 12px;
    line-height: 1.6;
}
</style>
