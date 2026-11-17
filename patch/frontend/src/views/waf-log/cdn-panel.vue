<template>
    <div class="policy-panel" v-loading="loading">
        <el-form label-width="92px" label-position="left">
            <el-form-item label="获取方式">
                <el-radio-group v-model="form.type" class="compact-segment">
                    <el-radio-button value="headers">按请求头列表</el-radio-button>
                    <el-radio-button value="header">指定单个请求头</el-radio-button>
                    <el-radio-button value="xff">X-Forwarded-For（最后一段）</el-radio-button>
                    <el-radio-button value="xff2">XFF（倒数第二段）</el-radio-button>
                    <el-radio-button value="xff3">XFF（倒数第三段）</el-radio-button>
                </el-radio-group>
            </el-form-item>

            <el-form-item v-if="form.type === 'headers'" label="请求头">
                <el-select
                    v-model="headerNames"
                    multiple
                    filterable
                    allow-create
                    default-first-option
                    collapse-tags
                    collapse-tags-tooltip
                    placeholder="按顺序取第一个非空的请求头"
                    class="pp-select"
                >
                    <el-option v-for="h in headerPresets" :key="h.value" :label="h.label" :value="h.value" />
                </el-select>
            </el-form-item>

            <el-form-item v-else-if="form.type === 'header'" label="请求头名">
                <el-input v-model="form.header" placeholder="x-real-ip" class="pp-select" />
            </el-form-item>

            <el-form-item>
                <el-button type="primary" :loading="saving" @click="save">保存并生效</el-button>
                <el-button v-if="scope === 'site'" @click="reset">恢复全局默认</el-button>
            </el-form-item>
        </el-form>

        <el-alert
            v-if="scope === 'site' && globalState !== 'on'"
            type="warning"
            :closable="false"
            title="全局 CDN 开关未开启，此处的真实 IP 识别不会生效，请先到全局设置打开"
            class="pp-alert"
        />
        <el-alert v-else type="info" :closable="false" class="pp-alert">
            <template #title>
                站点开启 + 全局开启同时满足才会采用真实 IP；识别到的 IP 会用于拦截日志、IP 黑名单、频率限制与地区限制。
            </template>
        </el-alert>
    </div>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus';
import { getWafPolicy, resetWafPolicy, saveWafPolicy } from '@/api/modules/waf-log';

const props = withDefaults(defineProps<{ scope?: 'site' | 'global'; siteKey?: string; active?: boolean }>(), {
    scope: 'site',
    siteKey: '',
    active: true,
});
const emit = defineEmits<{ (e: 'saved'): void }>();

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const headerPresets = [
    { value: 'x-forwarded-for', label: 'X-Forwarded-For' },
    { value: 'x-real-ip', label: 'X-Real-IP' },
    { value: 'proxy-client-ip', label: 'Proxy-Client-IP' },
    { value: 'wl-proxy-client-ip', label: 'WL-Proxy-Client-IP' },
    { value: 'http-client-ip', label: 'HTTP_CLIENT_IP' },
    { value: 'http-x-forwarded-for', label: 'HTTP_X_FORWARDED_FOR' },
    { value: 'cf-connecting-ip', label: 'CF-Connecting-IP（Cloudflare）' },
    { value: 'true-client-ip', label: 'True-Client-IP' },
    { value: 'x-client-ip', label: 'X-Client-IP' },
    { value: 'fastly-client-ip', label: 'Fastly-Client-IP' },
    { value: 'ali-cdn-real-ip', label: 'Ali-CDN-Real-IP（阿里云）' },
    { value: 'x-real-ip-cdn', label: 'X-Real-IP-CDN' },
];

const loading = ref(false);
const saving = ref(false);
const globalState = ref('off');
const form = ref<any>({ type: 'headers', header: 'x-real-ip', rules: [] });

const headerNames = computed({
    get: () => (form.value.rules || []).map((r: any) => (typeof r === 'string' ? r : r.rule)),
    set: (v: string[]) => {
        form.value.rules = v.map((x) => ({ rule: x, state: 'on' }));
    },
});

const load = async () => {
    loading.value = true;
    try {
        const d = unwrap(await getWafPolicy({ scope: props.scope, key: props.siteKey, name: 'cdn' }));
        const v = d.value || {};
        const g = d.global || {};
        globalState.value = g && g.state === 'on' ? 'on' : 'off';
        form.value = {
            type: ['headers', 'header', 'xff', 'xff2', 'xff3'].includes(v.type) ? v.type : 'headers',
            header: v.header || 'x-real-ip',
            rules: Array.isArray(v.rules) ? [...v.rules] : [],
        };
    } catch (e: any) {
        ElMessage.error('读取 CDN 配置失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const save = async () => {
    saving.value = true;
    try {
        await saveWafPolicy({
            scope: props.scope,
            key: props.siteKey,
            name: 'cdn',
            reload: true,
            value: {
                state: 'on',
                type: form.value.type,
                header: form.value.header,
                rules: form.value.rules,
            },
        });
        ElMessage.success('CDN 配置已保存并生效');
        emit('saved');
    } catch (e: any) {
        ElMessage.error(e?.message || '保存失败');
    } finally {
        saving.value = false;
    }
};

const reset = async () => {
    saving.value = true;
    try {
        await resetWafPolicy({ scope: 'site', key: props.siteKey, name: 'cdn' });
        ElMessage.success('已恢复为全局默认（默认关闭）');
        await load();
        emit('saved');
    } catch (e: any) {
        ElMessage.error(e?.message || '恢复失败');
    } finally {
        saving.value = false;
    }
};

watch(
    () => [props.siteKey, props.scope],
    () => {
        if (props.active) load();
    },
);
watch(
    () => props.active,
    (v) => {
        if (v) load();
    },
);
onMounted(() => {
    if (props.active) load();
});
</script>

<style scoped>
.policy-panel {
    padding: 4px 0 2px;
}
.pp-select {
    width: 100%;
    max-width: 520px;
}
.pp-alert {
    margin-top: 4px;
}
.compact-segment :deep(.el-radio-button__inner) {
    padding: 6px 10px;
}
</style>
