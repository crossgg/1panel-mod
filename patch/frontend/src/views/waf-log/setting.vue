<template>
    <LayoutContent title="全局设置" :divider="true">
        <template #leftToolBar>
            <el-button type="primary" :plain="topTab !== '1'" @click="switchTop('1')">频率限制</el-button>
            <el-button type="primary" :plain="topTab !== '2'" @click="switchTop('2')">默认规则</el-button>
            <el-button type="primary" :plain="topTab !== '3'" @click="switchTop('3')">自定义规则</el-button>
            <el-button type="primary" :plain="topTab !== '4'" @click="switchTop('4')">配置</el-button>
        </template>
        <template #main>
            <div v-loading="loading">
                <el-alert
                    v-if="errorMsg"
                    :title="errorMsg"
                    type="error"
                    show-icon
                    :closable="false"
                    class="mb-2"
                />

                <!-- WAF 主开关 -->
                <div class="waf-main-switch">
                    <div class="waf-main-switch__info">
                        <div class="waf-main-switch__title">
                            <span class="waf-main-switch__mark"></span>
                            <span>WAF 总开关</span>
                            <el-tag :type="wafState === 'on' ? 'success' : 'info'" effect="light">
                                {{ wafState === 'on' ? '已启用' : '已关闭' }}
                            </el-tag>
                        </div>
                        <span class="waf-main-switch__description">关闭之后所有网站将失去防护</span>
                    </div>
                    <el-switch
                        :model-value="wafState"
                        active-value="on"
                        inactive-value="off"
                        active-text="启动"
                        inactive-text="关闭"
                        inline-prompt
                        @change="toggleMain"
                    />
                </div>

                <el-alert type="info" :closable="false">
                    带有【网站】标签的设置，需要在【网站设置】配置生效，全局设置仅为新建网站的默认设置；设置生效需要【全局设置】和【
                    网站设置】的开关同时打开。
                </el-alert>

                <div v-if="cfg && cfg.waf" class="mt-2">
                    <!-- 1 频率限制 -->
                    <el-tabs v-if="topTab === '1'" v-model="sub1" tab-position="left" class="waf-sub-tabs">
                        <el-tab-pane label="访问频率限制" name="cc">
                            <ConfigCard
                                header="访问频率限制"
                                :description="ccDesc('cc')"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.cc.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('cc', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-form :model="cfg.cc" label-position="left" inline size="default">
                                        <el-form-item label="模式">
                                            <el-select v-model="cfg.cc.mode" class="p-w-200">
                                                <el-option label="全局模式" value="global" />
                                                <el-option label="URL 模式" value="uri" />
                                            </el-select>
                                        </el-form-item>
                                        <el-form-item label="周期">
                                            <el-input-number
                                                v-model="cfg.cc.duration"
                                                :min="10"
                                                :max="9999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item label="频率">
                                            <el-input-number
                                                v-model="cfg.cc.threshold"
                                                :min="1"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">次</span>
                                        </el-form-item>
                                        <el-form-item label="封禁时间">
                                            <el-input-number
                                                v-model="cfg.cc.ipBlockTime"
                                                :min="10"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button @click="saveCard('访问频率限制')">保存默认</el-button>
                                        </el-form-item>
                                    </el-form>
                                    <el-alert
                                        type="info"
                                        :closable="false"
                                        title="全局模式：单位时间请求任意 URL 次数之和超过阈值即触发；URL 模式：单位时间请求单个 URL 次数超过阈值即触发"
                                    />
                                    <el-alert
                                        type="warning"
                                        :closable="false"
                                        title="封锁 IP 临时存储在 OpenResty 中，重启 OpenResty 会解封，可以通过黑白名单永久拉黑"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="攻击频率限制" name="attackCount">
                            <ConfigCard header="攻击频率限制" :description="ccDesc('attackCount')">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.attackCount.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('attackCount', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-form :model="cfg.attackCount" label-position="left" inline>
                                        <el-form-item label="周期">
                                            <el-input-number
                                                v-model="cfg.attackCount.duration"
                                                :min="10"
                                                :max="9999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item label="频率">
                                            <el-input-number
                                                v-model="cfg.attackCount.threshold"
                                                :min="1"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">次</span>
                                        </el-form-item>
                                        <el-form-item label="封禁时间">
                                            <el-input-number
                                                v-model="cfg.attackCount.ipBlockTime"
                                                :min="10"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button @click="saveCard('攻击频率限制')">保存默认</el-button>
                                        </el-form-item>
                                    </el-form>
                                    <el-alert
                                        type="warning"
                                        :closable="false"
                                        title="封锁 IP 临时存储在 OpenResty 中，重启 OpenResty 会解封，可以通过黑白名单永久拉黑"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="404 频率限制" name="notFoundCount">
                            <ConfigCard header="404 频率限制" :description="ccDesc('notFoundCount')">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.notFoundCount.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('notFoundCount', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-form :model="cfg.notFoundCount" label-position="left" inline>
                                        <el-form-item label="周期">
                                            <el-input-number
                                                v-model="cfg.notFoundCount.duration"
                                                :min="10"
                                                :max="9999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item label="频率">
                                            <el-input-number
                                                v-model="cfg.notFoundCount.threshold"
                                                :min="1"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">次</span>
                                        </el-form-item>
                                        <el-form-item label="封禁时间">
                                            <el-input-number
                                                v-model="cfg.notFoundCount.ipBlockTime"
                                                :min="10"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button @click="saveCard('404 频率限制')">保存默认</el-button>
                                        </el-form-item>
                                    </el-form>
                                    <el-alert
                                        type="warning"
                                        :closable="false"
                                        title="封锁 IP 临时存储在 OpenResty 中，重启 OpenResty 会解封，可以通过黑白名单永久拉黑"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="URL 频率限制" name="urlcc">
                            <ConfigCard
                                header="URL 频率限制"
                                description="为单个 URL 设置访问频率，具体阈值在【网站设置】中维护"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.urlcc.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('urlcc', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-form :model="cfg.urlcc" label-position="left" inline>
                                        <el-form-item label="封禁时间">
                                            <el-input-number
                                                v-model="cfg.urlcc.ipBlockTime"
                                                :min="10"
                                                :max="99999999"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">秒</span>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button @click="saveCard('URL 频率限制')">保存默认</el-button>
                                        </el-form-item>
                                    </el-form>
                                </template>
                            </ConfigCard>
                        </el-tab-pane>
                    </el-tabs>

                    <!-- 2 默认规则 -->
                    <el-tabs v-else-if="topTab === '2'" v-model="sub2" tab-position="left" class="waf-sub-tabs">
                        <el-tab-pane
                            v-for="it in defaultRuleItems"
                            :key="it.scope"
                            :label="it.label"
                            :name="it.scope"
                        >
                            <ConfigCard :header="it.label" :description="it.desc">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg[it.scope].state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle(it.scope, v)"
                                    />
                                </template>
                                <template #content-form>
                                    <div class="rule-line">
                                        <span class="rule-count">
                                            已启用 <b>{{ ruleCount(it.file).enabled }}</b> / 共
                                            {{ ruleCount(it.file).total }} 条
                                        </span>
                                        <el-button type="primary" link @click="gotoRule(it.file)">
                                            维护条目
                                        </el-button>
                                    </div>
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="补充规则" name="vuln">
                            <ConfigCard
                                header="补充规则"
                                description="包含常见软件、框架的漏洞（CVE）特征，拦截已知漏洞利用请求"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.vuln.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('vuln', v)"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="其他" name="other">
                            <ConfigCard header="SQL 注入防御" description="识别请求中的 SQL 注入并拦截">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.sql.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('sql', v)"
                                    />
                                </template>
                            </ConfigCard>
                            <ConfigCard header="XSS 防御" description="识别请求中的 XSS 并拦截" class="mt-1.5">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.xss.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('xss', v)"
                                    />
                                </template>
                            </ConfigCard>
                            <ConfigCard header="严格模式" description="使用更严格的规则来校验请求" class="mt-1.5">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.strict.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('strict', v)"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>
                    </el-tabs>

                    <!-- 3 自定义规则 -->
                    <el-tabs v-else-if="topTab === '3'" v-model="sub3" tab-position="left" class="waf-sub-tabs">
                        <el-tab-pane label="自定义规则" name="acl">
                            <ConfigCard
                                header="自定义规则"
                                description="按 URL / 请求头 / Cookie / 参数 / User-Agent / HTTP 方法匹配并拦截；这里维护的是默认规则，新建网站会继承，已建网站需在【网站设置】中单独配置"
                            >
                                <template #content-form>
                                    <RuleInline
                                        scope="global"
                                        :files="['urlBlack', 'uaBlack', 'header', 'cookie', 'args', 'methodWhite']"
                                        @changed="load"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="文件上传限制" name="fileExt">
                            <ConfigCard header="文件上传限制" description="禁止上传的文件扩展名">
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.fileExt.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('fileExt', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <RuleInline scope="global" :files="['fileExt']" @changed="load" />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="地区访问限制" name="geo">
                            <ConfigCard
                                header="地区访问限制（总开关）"
                                description="此开关是所有网站地区限制的总开关；下面的默认策略只作为新建站点的模板，已建站点需在【网站设置】中单独配置"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.geoRestrict.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('geoRestrict', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-alert
                                        v-if="cfg.geoRestrict.state !== 'on'"
                                        type="warning"
                                        :closable="false"
                                        title="总开关未开启时，任何站点的地区限制都不会生效"
                                    />
                                    <GeoPanel scope="global" />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="CDN" name="cdn">
                            <ConfigCard
                                header="CDN（总开关）"
                                description="此开关是所有网站真实 IP 识别的总开关；站点侧还需各自开启并选择请求头，识别结果用于拦截日志、IP 黑名单、频率限制与地区限制"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.cdn.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('cdn', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-alert
                                        v-if="cfg.cdn.state !== 'on'"
                                        type="warning"
                                        :closable="false"
                                        title="总开关未开启时，站点即使选了请求头也不会采用真实 IP"
                                    />
                                </template>
                            </ConfigCard>
                        </el-tab-pane>
                    </el-tabs>

                    <!-- 4 配置 -->
                    <el-tabs v-else v-model="sub4" tab-position="left" class="waf-sub-tabs">
                        <el-tab-pane label="拦截页面" name="html">
                            <ConfigCard
                                header="拦截页面"
                                description="命中规则后返回给访客的页面，支持自定义 HTML；修改后立即生效，无需重载"
                            >
                                <template #content-form>
                                    <div class="html-picker">
                                        <el-radio-group v-model="htmlName" class="compact-segment" @change="loadHtml">
                                            <el-radio-button v-for="p in htmlPages" :key="p.name" :value="p.name">
                                                {{ p.label }}
                                            </el-radio-button>
                                        </el-radio-group>
                                        <el-tag v-if="htmlModified" type="warning" effect="light" size="small">
                                            已自定义
                                        </el-tag>
                                    </div>
                                    <div class="html-tip">
                                        页面文件：data/default/{{ htmlName }}
                                        <span v-if="htmlSize">· {{ htmlSize }} 字节</span>
                                    </div>
                                    <el-input
                                        v-model="htmlContent"
                                        type="textarea"
                                        :rows="18"
                                        resize="vertical"
                                        spellcheck="false"
                                        placeholder="<!DOCTYPE html> ..."
                                        class="html-editor"
                                    />
                                    <div class="html-actions">
                                        <el-button type="primary" :loading="htmlSaving" @click="saveHtml">
                                            保存
                                        </el-button>
                                        <el-button :disabled="!htmlModified" @click="revertHtml">还原默认</el-button>
                                        <el-button @click="loadHtml">重新读取</el-button>
                                        <span class="html-hint" v-pre>支持完整 HTML/CSS，保存后立即生效；重载 OpenResty 不影响自定义内容</span>
                                    </div>
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="日志" name="log">
                            <ConfigCard
                                header="访问日志"
                                description="记录请求量、状态码与攻击记录，是概览与拦截日志的数据来源"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.log.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('log', v)"
                                    />
                                </template>
                                <template #content-form>
                                    <el-form :model="cfg.log" label-position="left" inline>
                                        <el-form-item label="保留天数">
                                            <el-input-number
                                                v-model="cfg.log.maxDay"
                                                :min="1"
                                                :max="3650"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">天</span>
                                        </el-form-item>
                                        <el-form-item label="单库上限">
                                            <el-input-number
                                                v-model="cfg.log.maxSize"
                                                :min="1"
                                                :max="10240"
                                                controls-position="right"
                                                class="p-w-150"
                                            />
                                            <span class="unit">MB</span>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button @click="saveCard('日志')">保存默认</el-button>
                                        </el-form-item>
                                    </el-form>
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="其他" name="other">
                            <ConfigCard
                                header="恶意 IP 组"
                                description="从互联网收集的一些恶意 IP，阻止其访问"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.defaultIpBlack.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('defaultIpBlack', v)"
                                    />
                                </template>
                            </ConfigCard>
                            <ConfigCard
                                header="未授权域名访问"
                                description="请求的域名不在本站点中时直接拦截"
                                class="mt-1.5"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.unknownWebsite.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('unknownWebsite', v)"
                                    />
                                </template>
                            </ConfigCard>
                            <ConfigCard
                                header="蜘蛛放行"
                                description="开启后按蜘蛛 IP 池放行搜索引擎爬虫，关闭后所有蜘蛛访问都会被拦截"
                                class="mt-1.5"
                            >
                                <template #header-r>
                                    <el-switch
                                        v-model="cfg.allowSpider.state"
                                        active-value="on"
                                        inactive-value="off"
                                        @change="(v) => toggle('allowSpider', v)"
                                    />
                                </template>
                            </ConfigCard>
                            <ConfigCard
                                header="黑白名单"
                                description="IP / URL / User-Agent 的黑白名单统一在【黑白名单】页面维护"
                                class="mt-1.5"
                            >
                                <template #content-form>
                                    <div class="rule-line">
                                        <span class="rule-count">
                                            IP {{ ruleCount('ipBlack.json').total + ruleCount('ipWhite.json').total }}
                                            · URL {{ ruleCount('urlBlack.json').total + ruleCount('urlWhite.json').total }}
                                            · UA {{ ruleCount('uaBlack.json').total + ruleCount('uaWhite.json').total }}
                                        </span>
                                        <el-button type="primary" link @click="router.push('/waf-log/blackwhite')">
                                            前往维护
                                        </el-button>
                                    </div>
                                </template>
                            </ConfigCard>
                        </el-tab-pane>

                        <el-tab-pane label="IP 库" name="geodb">
                            <GeoDb />
                        </el-tab-pane>
                    </el-tabs>
                </div>
            </div>
        </template>
    </LayoutContent>
</template>

<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus';
import ConfigCard from '@/components/config-card/index.vue';
import GeoPanel from './geo-panel.vue';
import GeoDb from './geo-db.vue';
import RuleInline from './rule-inline.vue';
import {
    getWafConfig,
    saveWafConfig,
    setWafState,
    getWafHtmlList,
    getWafHtml,
    saveWafHtml,
    revertWafHtml,
} from '@/api/modules/waf-log';

const router = useRouter();

const loading = ref(false);
const errorMsg = ref('');
const confDir = ref('');
const emptyCfg = () => ({
    waf: { state: 'off' },
    sql: { state: 'off' },
    xss: { state: 'off' },
    strict: { state: 'off' },
    args: { state: 'off' },
    cookie: { state: 'off' },
    header: { state: 'off' },
    methodWhite: { state: 'off' },
    defaultUaBlack: { state: 'off' },
    defaultUrlBlack: { state: 'off' },
    defaultIpBlack: { state: 'off' },
    unknownWebsite: { state: 'off' },
    allowSpider: { state: 'off' },
    fileExt: { state: 'off' },
    geoRestrict: { state: 'off', action: 'deny', rules: [], provinceRules: [] },
    cdn: { state: 'off', type: 'headers', rules: [] },
    urlcc: { state: 'off' },
    vuln: { state: 'off' },
    log: { state: 'off', maxDay: 180, maxSize: 500 },
    cc: { state: 'off', duration: 10, threshold: 100, ipBlockTime: 600 },
    attackCount: { state: 'off', duration: 10, threshold: 100, ipBlockTime: 600 },
    notFoundCount: { state: 'off', duration: 10, threshold: 100, ipBlockTime: 600 },
    acl: { state: 'off' },
});
const cfg = ref<any>(emptyCfg());
const rules = ref<any[]>([]);

const topTab = ref(localStorage.getItem('waf-global-tab') || '1');
const sub1 = ref(localStorage.getItem('waf-global-cc-tab') || 'cc');
const sub2 = ref(localStorage.getItem('waf-global-default-tab') || 'args');
const sub3 = ref(localStorage.getItem('waf-global-custom-tab') || 'acl');
const sub4 = ref(localStorage.getItem('waf-global-setting-tab') || 'html');

// ---------- 拦截页面自定义 ----------
const htmlPages = ref<any[]>([]);
const htmlName = ref('forbidden.html');
const htmlContent = ref('');
const htmlSize = ref(0);
const htmlModified = ref(false);
const htmlSaving = ref(false);

const unwrap = (res: any) => (res && res.data !== undefined ? res.data : {});

const initHtml = async () => {
    try {
        const d = unwrap(await getWafHtmlList());
        htmlPages.value = d.items || [];
        const first = htmlPages.value.find((p: any) => p.name === htmlName.value) || htmlPages.value[0];
        if (first) htmlName.value = first.name;
        htmlModified.value = !!first?.modified;
        await loadHtml();
    } catch (e: any) {
        ElMessage.error('读取拦截页面失败：' + (e?.message || e));
    }
};

const loadHtml = async () => {
    if (!htmlName.value) return;
    try {
        const d = unwrap(await getWafHtml(htmlName.value));
        htmlContent.value = d.content || '';
        htmlSize.value = d.size || 0;
        const hit = htmlPages.value.find((p: any) => p.name === htmlName.value);
        htmlModified.value = !!hit?.modified;
    } catch (e: any) {
        htmlContent.value = '';
        htmlSize.value = 0;
        ElMessage.error('读取页面失败：' + (e?.message || e));
    }
};

const saveHtml = async () => {
    if (!htmlName.value) return;
    if (!htmlContent.value.trim()) {
        ElMessage.warning('页面内容不能为空');
        return;
    }
    htmlSaving.value = true;
    try {
        const d = unwrap(await saveWafHtml({ name: htmlName.value, content: htmlContent.value, reload: false }));
        if (d.saved) ElMessage.success('拦截页面已保存');
        const hit = htmlPages.value.find((p: any) => p.name === htmlName.value);
        if (hit) hit.modified = true;
        htmlModified.value = true;
        htmlSize.value = new Blob([htmlContent.value]).size;
    } catch (e: any) {
        ElMessage.error('保存失败：' + (e?.message || e));
    } finally {
        htmlSaving.value = false;
    }
};

const revertHtml = async () => {
    try {
        await ElMessageBox.confirm(`是否把「${htmlName.value}」还原为出厂页面？`, '还原默认', {
            confirmButtonText: '确认',
            cancelButtonText: '取消',
            type: 'warning',
        });
    } catch {
        return;
    }
    try {
        const d = unwrap(await revertWafHtml({ name: htmlName.value, reload: false }));
        if (d.saved) ElMessage.success('已还原默认页面');
        await initHtml();
    } catch (e: any) {
        ElMessage.error('还原失败：' + (e?.message || e));
    }
};

const switchTop = (v: string) => {
    topTab.value = v;
    localStorage.setItem('waf-global-tab', v);
};

const wafState = computed(() => cfg.value?.waf?.state || 'off');

const defaultRuleItems = [
    { scope: 'args', label: '参数规则', file: 'args.json', desc: '禁止请求中携带恶意参数' },
    { scope: 'defaultUrlBlack', label: 'URL 规则', file: 'defaultUrlBlack.json', desc: '禁止访问的 URL' },
    { scope: 'methodWhite', label: 'HTTP 规则', file: 'methodWhite.json', desc: '设置允许访问的方法类型，如果想限制某些类型访问，请关闭这个类型的按钮，例如：仅允许 GET 类型访问，那么需要关闭除了 GET 之外的其他类型按钮' },
    { scope: 'cookie', label: 'Cookie 规则', file: 'cookie.json', desc: '禁止请求中携带恶意 Cookie' },
    { scope: 'header', label: 'Header 规则', file: 'header.json', desc: '禁止请求中携带恶意 Header' },
    { scope: 'defaultUaBlack', label: 'User-Agent 规则', file: 'defaultUaBlack.json', desc: '包含常见的恶意爬虫规则' },
];

// 秒数按官方 ccHelper 的口径拼装说明文案
const ccDesc = (scope: string) => {
    const m = cfg.value?.[scope] || {};
    const t = Number(m.duration || 0);
    const n = Number(m.threshold || 0);
    const b = formatDuration(Number(m.ipBlockTime || 0));
    if (scope === 'cc') return `${t} 秒内累计请求任意网站超过 ${n} 次，封锁此 IP ${b}`;
    if (scope === 'attackCount') return `${t} 秒内累计拦截超过 ${n} 次，封锁此 IP ${b}`;
    return `${t} 秒内累计请求返回 404 超过 ${n} 次，封锁此 IP ${b}`;
};

const formatDuration = (sec: number) => {
    if (!sec) return '0 秒';
    if (sec % 86400 === 0) return `${sec / 86400} 天`;
    if (sec % 3600 === 0) return `${sec / 3600} 小时`;
    if (sec % 60 === 0) return `${sec / 60} 分钟`;
    return `${sec} 秒`;
};

const ruleCount = (file: string) => {
    const hit = (rules.value || []).find((r: any) => r.name === file);
    return { total: hit?.total || 0, enabled: hit?.enabled || 0 };
};

const gotoRule = (file: string) => {
    router.push({ path: '/waf-log/custom', query: { file } });
};

const load = async () => {
    loading.value = true;
    errorMsg.value = '';
    try {
        const res = await getWafConfig();
        const d = res?.data || {};
        confDir.value = d.conf_dir || '';
        rules.value = d.rules || [];
        const g = d.global || {};
        // 补齐缺失的模块，避免模板取值报错
        const need = [
            'waf', 'sql', 'xss', 'strict', 'args', 'cookie', 'header', 'methodWhite',
            'defaultUaBlack', 'defaultUrlBlack', 'defaultIpBlack', 'unknownWebsite', 'allowSpider',
            'fileExt', 'geoRestrict', 'cdn', 'urlcc', 'vuln', 'log',
            'cc', 'attackCount', 'notFoundCount',
        ];
        need.forEach((k) => {
            if (!g[k] || typeof g[k] !== 'object') g[k] = { state: 'off' };
            if (k === 'log') {
                if (g[k].maxDay == null) g[k].maxDay = 180;
                if (g[k].maxSize == null) g[k].maxSize = 500;
            }
            if (['cc', 'attackCount', 'notFoundCount'].includes(k)) {
                if (g[k].duration == null) g[k].duration = 10;
                if (g[k].threshold == null) g[k].threshold = 100;
                if (g[k].ipBlockTime == null) g[k].ipBlockTime = 600;
                if (k === 'cc' && !g[k].mode) g[k].mode = 'uri';
            }
        });
        cfg.value = g;
    } catch (e: any) {
        errorMsg.value = e?.message || '配置读取失败';
    } finally {
        loading.value = false;
    }
};

const toggle = async (scope: string, state: any) => {
    const target = String(state);
    try {
        const res = await setWafState({ scope, state: target });
        const d = res?.data || {};
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning(`已写盘，但重载失败：${d.reload_error}`);
        } else {
            ElMessage.success('操作成功');
        }
        load();
    } catch {
        load();
    }
};

const toggleMain = async (v: any) => {
    const target = String(v);
    cfg.value.waf.state = target;
    if (target === 'off') {
        try {
            await ElMessageBox.confirm('关闭 WAF 会使网站失去防护，是否继续', '关闭 WAF', {
                confirmButtonText: '确认',
                cancelButtonText: '取消',
                type: 'warning',
            });
        } catch {
            cfg.value.waf.state = 'on';
            return;
        }
    }
    await toggle('waf', target);
};

const saveCard = async (label: string) => {
    loading.value = true;
    try {
        const res = await saveWafConfig({ global: cfg.value, reload: true });
        const d = res?.data || {};
        if (d.reloaded === false && d.reload_error) {
            ElMessage.warning(`${label}已写盘，但重载失败：${d.reload_error}`);
        } else {
            ElMessage.success(`${label}已保存`);
        }
        if (d.warnings && d.warnings.length) ElMessage.warning(d.warnings.join('；'));
        await load();
    } catch (e: any) {
        ElMessage.error(e?.message || '保存失败');
    } finally {
        loading.value = false;
    }
};

onMounted(() => {
    load();
    initHtml();
});
</script>

<style scoped>
.waf-main-switch {
    border: 1px solid var(--el-border-color-light);
    border-left: 4px solid var(--el-color-primary);
    background: var(--el-fill-color-extra-light);
    border-radius: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-bottom: 10px;
    padding: 14px 18px;
}
.waf-main-switch__info {
    min-width: 0;
}
.waf-main-switch__title {
    color: var(--el-text-color-primary);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    font-size: 16px;
    font-weight: 600;
    line-height: 22px;
}
.waf-main-switch__mark {
    background: var(--el-color-primary);
    border-radius: 50%;
    width: 8px;
    height: 8px;
}
.waf-main-switch__description {
    color: var(--el-text-color-secondary);
    margin-top: 6px;
    font-size: 13px;
    line-height: 20px;
    display: block;
}
.waf-sub-tabs {
    min-height: 420px;
}
.rule-line {
    display: flex;
    align-items: center;
    gap: 16px;
}
.rule-count {
    color: var(--el-text-color-secondary);
    font-size: 13px;
}
.rule-count b {
    color: var(--el-color-primary);
}
.unit {
    margin-left: 6px;
    color: var(--el-text-color-secondary);
    font-size: 13px;
}
.p-w-150 {
    width: 150px;
}
.p-w-200 {
    width: 200px;
}
.mb-1 {
    margin-bottom: 4px;
}
/* 拦截页面编辑器 */
.compact-segment :deep(.el-radio-button__inner) {
    padding: 6px 10px;
    border-left-width: 0;
}
.compact-segment :deep(.el-radio-button:first-child .el-radio-button__inner) {
    border-left-width: 1px;
}
.html-picker {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}
.html-tip {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    margin-bottom: 8px;
}
.html-editor :deep(textarea) {
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.55;
}
.html-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 10px;
}
.html-hint {
    color: var(--el-text-color-placeholder);
    font-size: 12px;
    margin-left: 4px;
}
</style>
