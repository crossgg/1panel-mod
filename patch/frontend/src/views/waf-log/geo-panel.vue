<template>
    <div class="policy-panel" v-loading="loading">
        <el-form label-width="92px" label-position="left">
            <el-form-item label="访问策略">
                <el-radio-group v-model="form.action" class="compact-segment">
                    <el-radio-button value="deny">拦截所选地区</el-radio-button>
                    <el-radio-button value="allow">仅允许所选地区</el-radio-button>
                </el-radio-group>
                <span class="pp-hint">{{ form.action === 'deny' ? '命中名单内的国家/省份即拦截' : '名单外的国家/省份一律拦截' }}</span>
            </el-form-item>
            <el-form-item label="国家/地区">
                <el-select
                    v-model="form.rules"
                    multiple
                    filterable
                    allow-create
                    default-first-option
                    collapse-tags
                    collapse-tags-tooltip
                    placeholder="选择或直接输入 ISO 代码，如 CN、US"
                    class="pp-select"
                >
                    <el-option v-for="c in countries" :key="c.iso" :label="`${c.zh}（${c.iso}）`" :value="c.iso" />
                </el-select>
            </el-form-item>
            <el-form-item label="中国省份">
                <el-select
                    v-model="form.provinceRules"
                    multiple
                    filterable
                    allow-create
                    default-first-option
                    collapse-tags
                    collapse-tags-tooltip
                    placeholder="不限制省份可留空"
                    class="pp-select"
                >
                    <el-option v-for="p in provinces" :key="p.en" :label="`${p.zh}（${p.en}）`" :value="p.en" />
                </el-select>
            </el-form-item>
            <el-form-item v-if="form.provinceRules.length" label="省份策略">
                <el-radio-group v-model="form.provinceAction" class="compact-segment">
                    <el-radio-button value="deny">拦截所选省份</el-radio-button>
                    <el-radio-button value="allow">仅允许所选省份</el-radio-button>
                </el-radio-group>
            </el-form-item>
            <el-form-item label="城市功能状态">
                <div class="city-steps">
                    <el-tag size="small" :type="openrestyReady ? 'success' : 'danger'">
                        ① OpenResty {{ openrestyReady ? '已就绪' : '未安装' }}
                    </el-tag>
                    <el-tag size="small" :type="patchApplied ? 'success' : 'warning'">
                        ② Lua 补丁 {{ patchApplied ? '已应用' : '未应用' }}
                    </el-tag>
                    <el-tag size="small" :type="cityReady ? 'success' : 'warning'">
                        ③ 城市库 {{ cityReady ? '已就绪' : '需 GeoLite2-City' }}
                    </el-tag>
                </div>
                <div v-if="cityPatchHint" class="pp-hint" style="margin-left: 0">{{ cityPatchHint }}</div>
            </el-form-item>
            <el-form-item label="中国城市">
                <el-select
                    v-model="form.cityRules"
                    multiple
                    filterable
                    allow-create
                    default-first-option
                    collapse-tags
                    collapse-tags-tooltip
                    :disabled="!cityReady"
                    :placeholder="cityReady ? '不限制城市可留空' : cityHint || '当前 IP 库不含城市信息'"
                    class="pp-select"
                >
                    <el-option v-for="c in cities" :key="c.en" :label="`${c.zh}（${c.en}）`" :value="c.en" />
                </el-select>
            </el-form-item>
            <el-form-item v-if="form.cityRules.length" label="城市策略">
                <el-radio-group v-model="form.cityAction" class="compact-segment">
                    <el-radio-button value="deny">拦截所选城市</el-radio-button>
                    <el-radio-button value="allow">仅允许所选城市</el-radio-button>
                </el-radio-group>
            </el-form-item>
            <el-form-item v-if="!patchApplied && openrestyReady" label="城市补丁">
                <el-button size="small" type="warning" :loading="patching" @click="applyPatch">应用城市补丁并生效</el-button>
                <span class="pp-hint">需往 openresty 挂载卷写入 Lua 补丁并 reload</span>
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
            title="全局「地区访问限制」未开启，站点策略不会生效，请先到全局设置打开总开关"
            class="pp-alert"
        />
        <el-alert
            v-else
            type="info"
            :closable="false"
            class="pp-alert"
        >
            <template #title>
                省份/城市值需与 IP 库中的英文名一致（如 Zhejiang / Guangzhou）；留空即不限制；内网与回环地址不做地区判断。
                城市限制需 GeoLite2-City 库 + Lua 补丁（{{ patchApplied ? '已应用' : '未应用' }}）。
            </template>
        </el-alert>
    </div>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus';
import {
    getWafGeoOptions,
    getWafGeoCities,
    getWafGeoCityStatus,
    applyWafGeoCityPatch,
    getWafPolicy,
    resetWafPolicy,
    saveWafPolicy,
} from '@/api/modules/waf-log';

const props = withDefaults(defineProps<{ scope?: 'site' | 'global'; siteKey?: string; active?: boolean }>(), {
    scope: 'site',
    siteKey: '',
    active: true,
});
const emit = defineEmits<{ (e: 'saved'): void }>();

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const loading = ref(false);
const saving = ref(false);
const countries = ref<any[]>([]);
const provinces = ref<any[]>([]);
const globalState = ref('off');
const cities = ref<any[]>([]);
const cityReady = ref(false);
const cityHint = ref('');
const patchApplied = ref(false);
const openrestyReady = ref(true);
const cityPatchHint = ref('');
const patching = ref(false);
const form = ref<any>({ action: 'deny', rules: [], provinceAction: 'deny', provinceRules: [], cityAction: 'deny', cityRules: [] });

const load = async () => {
    loading.value = true;
    try {
        if (!countries.value.length) {
            const o = unwrap(await getWafGeoOptions());
            countries.value = o.countries || [];
            provinces.value = o.provinces || [];
            globalState.value = o.global_geo_state || 'off';
        }
        const [cd, ps] = await Promise.all([getWafGeoCities(), getWafGeoCityStatus()]);
        const c = unwrap(cd);
        cities.value = c.cities || [];
        cityReady.value = !!c.ready;
        cityHint.value = c.hint || '';
        const st = unwrap(ps);
        patchApplied.value = !!st.applied;
        openrestyReady.value = st.openresty_ready !== false;
        cityPatchHint.value = st.hint || '';
        const d = unwrap(await getWafPolicy({ scope: props.scope, key: props.siteKey, name: 'geoRestrict' }));
        const v = d.value || {};
        form.value = {
            action: v.action === 'allow' ? 'allow' : 'deny',
            rules: Array.isArray(v.rules) ? [...v.rules] : [],
            provinceAction: v.provinceAction === 'allow' ? 'allow' : 'deny',
            provinceRules: Array.isArray(v.provinceRules) ? [...v.provinceRules] : [],
            cityAction: v.cityAction === 'allow' ? 'allow' : 'deny',
            cityRules: Array.isArray(v.cityRules) ? [...v.cityRules] : [],
        };
    } catch (e: any) {
        ElMessage.error('读取地区策略失败：' + (e?.message || e));
    } finally {
        loading.value = false;
    }
};

const save = async () => {
    saving.value = true;
    try {
        const pay = {
            scope: props.scope,
            key: props.siteKey,
            name: 'geoRestrict',
            reload: true,
            value: {
                state: 'on',
                action: form.value.action,
                rules: form.value.rules,
                provinceAction: form.value.provinceAction,
                provinceRules: form.value.provinceRules,
                cityAction: form.value.cityAction,
                cityRules: form.value.cityRules,
            },
        };
        await saveWafPolicy(pay);
        ElMessage.success('地区策略已保存并生效');
        emit('saved');
    } catch (e: any) {
        ElMessage.error(e?.message || '保存失败');
    } finally {
        saving.value = false;
    }
};

const applyPatch = async () => {
    patching.value = true;
    try {
        await applyWafGeoCityPatch();
        patchApplied.value = true;
        ElMessage.success('城市补丁已写入挂载卷并 reload 生效');
    } catch (e: any) {
        ElMessage.error(e?.message || '应用补丁失败');
    } finally {
        patching.value = false;
    }
};

const reset = async () => {
    saving.value = true;
    try {
        await resetWafPolicy({ scope: 'site', key: props.siteKey, name: 'geoRestrict' });
        ElMessage.success('已恢复为全局默认（默认关闭，需重新开启）');
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
.city-steps {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.pp-hint {
    margin-left: 10px;
    color: var(--el-text-color-secondary);
    font-size: 12px;
}
.pp-alert {
    margin-top: 4px;
}
.compact-segment :deep(.el-radio-button__inner) {
    padding: 6px 10px;
}
</style>
