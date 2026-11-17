<template>
    <div ref="el" class="waf-echart" :style="{ height: height }" />
</template>

<script setup lang="ts">
// WAF 页面用的原生 echarts 封装（补丁文件，新增）
//
// 为什么不直接用 @/components/v-charts：
//   Line.vue 只认 { xData, yData:[{name,data}] }，Pie.vue 是「百分比进度环」只认 { data:number }，
//   跟标准 echarts option 不是一回事。WAF 概览需要标准 option（多 series / 饼图 / 枚举 x 轴），
//   所以这里直接用 @/utils/echarts 建实例。
import { onBeforeUnmount, onMounted, nextTick, ref, watch } from 'vue';
import echarts from '@/utils/echarts';

const props = withDefaults(
    defineProps<{
        option: any;
        height?: string;
    }>(),
    { height: '280px' },
);

const el = ref<HTMLElement>();
let chart: any = null;

const render = () => {
    if (!el.value || !props.option) return;
    if (!chart) {
        chart = echarts.init(el.value);
    }
    chart.setOption(props.option, true);
    chart.resize();
};

const onResize = () => {
    chart?.resize();
};

watch(
    () => props.option,
    () => nextTick(render),
    { deep: true },
);

watch(
    () => props.height,
    () => nextTick(onResize),
);

onMounted(() => {
    nextTick(render);
    window.addEventListener('resize', onResize);
});

onBeforeUnmount(() => {
    window.removeEventListener('resize', onResize);
    chart?.dispose();
    chart = null;
});
</script>

<style scoped>
.waf-echart {
    width: 100%;
}
</style>
