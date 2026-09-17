<template>
  <div class="playbook-page" v-if="p">
    <!-- 返回 -->
    <div class="pb-back">
      <button class="cc-text-button" type="button" @click="$router.push('/datasets')">← 返回数据集列表</button>
    </div>

    <!-- 区块一:剧本页头 -->
    <section class="cc-panel pb-hero">
      <div class="pb-hero-main">
        <div class="pb-hero-left">
          <div class="pb-hero-kicker">PLAYBOOK · 剧本 #{{ String(p.seqNo).padStart(2, '0') }}</div>
          <h1 class="pb-hero-name">{{ groupName }}</h1>
          <div class="pb-hero-sub">
            <span class="pb-hero-code">{{ p.threatGroup }}</span>
            <span v-if="p.attackDate" class="pb-hero-dot">·</span>
            <span v-if="p.attackDate">{{ p.attackDate }}</span>
            <span class="pb-hero-dot">·</span>
            <span>{{ p.stepCount }} 步攻击链</span>
          </div>
        </div>
        <span v-if="p.downloadable === 1" class="pb-ready-badge">✓ 开放下载</span>
        <span v-else class="pb-lock-badge">ⓘ 需申请</span>
      </div>
      <div class="pb-hero-divider"></div>
      <p class="pb-hero-desc">{{ p.description }}</p>
      <div class="pb-stat-bar">
        <div class="pb-stat"><b>{{ p.stepCount }}</b><span>攻击步骤</span></div>
        <div class="pb-stat"><b>{{ p.eventCount }}</b><span>标注黑事件</span></div>
        <div class="pb-stat"><b>{{ p.techniqueCount }}</b><span>ATT&CK 技术</span></div>
        <div class="pb-stat"><b>{{ p.hostCount }}</b><span>涉及主机</span></div>
        <div class="pb-stat"><b>{{ p.fileCount }}</b><span>数据文件</span></div>
        <div class="pb-stat"><b>{{ sizeText }}</b><span>数据规模</span></div>
      </div>
      <div class="pb-hero-actions">
        <button v-if="p.downloadable === 1" class="cc-primary-button" type="button" @click="download">
          <svg viewBox="0 0 24 24" width="14" height="14"><path d="M12 4v12m-5-5 5 5 5-5M5 20h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          打包下载({{ sizeText }})
        </button>
        <button v-else class="cc-primary-button" type="button" @click="openApply">
          <svg viewBox="0 0 24 24" width="14" height="14"><path d="M12 4v12m-5-5 5 5 5-5M5 20h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
          申请下载该剧本
        </button>
        <span class="pb-download-count" v-if="p.downloadable === 1">已下载 {{ p.downloadCount || 0 }} 次</span>
        <span class="pb-download-tip" v-else>该剧本暂未开放直接下载,提交申请经管理员审核后开放。</span>
      </div>
    </section>

    <!-- 区块二:攻击链步骤 -->
    <section class="cc-panel">
      <div class="cc-section-head">
        <div>
          <span class="cc-section-kicker">ATTACK CHAIN</span>
          <h2>攻击链步骤</h2>
        </div>
      </div>
      <div class="pb-steps">
        <div v-for="st in steps" :key="st.id" class="pb-step">
          <div class="pb-step-no">{{ st.stepNo }}</div>
          <div class="pb-step-main">
            <p class="pb-step-activity">{{ st.activity }}</p>
            <p class="pb-step-meta">
              <span class="pb-step-actor">{{ st.actor }} @ {{ st.system }}</span>
              <span v-if="st.tacticName" class="pb-tactic">{{ st.tacticId }} {{ st.tacticName }}</span>
              <span v-for="et in parseJson(st.eventTypes)" :key="et" class="pb-evtype">{{ et }}</span>
            </p>
            <div v-if="parseJson(st.techniques).length" class="pb-tech-row">
              <span v-for="t in parseJson(st.techniques)" :key="t" class="pb-tech">{{ t }}</span>
            </div>
          </div>
        </div>
        <p v-if="!steps.length" class="pb-empty">该剧本暂无步骤数据。</p>
      </div>
    </section>

    <!-- 区块三:数据目录与下载 -->
    <section class="cc-panel">
      <div class="cc-section-head">
        <div>
          <span class="cc-section-kicker">DOWNLOAD</span>
          <h2>数据包内容与下载</h2>
        </div>
      </div>
      <p class="pkg-tip">下载得到 {{ p.packageName || p.code + '.tar.gz' }}(解压后 {{ p.dataSizeMb >= 1024 ? (p.dataSizeMb / 1024).toFixed(1) + ' GB' : p.dataSizeMb + ' MB' }},共 {{ p.fileCount }} 个文件),一级目录结构如下:</p>
      <div class="pkg-list">
        <div class="pkg-row">
          <code class="pkg-name">data/</code>
          <span class="pkg-use">多源异构日志,按主机分目录:Windows 安全事件 / Sysmon(XML)、eCAR 审计(JSON)、Web 访问日志、bash 历史、Zeek 网络日志(dns/http/ssl 等)</span>
        </div>
        <div class="pkg-row" v-if="p.artifactCount > 0">
          <code class="pkg-name">artifacts/</code>
          <span class="pkg-use">攻击样本原件(如钓鱼邮件 .eml、诱饵文档),本剧本含 {{ p.artifactCount }} 个</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">GROUND_TRUTH.md</code>
          <span class="pkg-use">攻击链步骤与时间线标注,人读版</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">GROUND_TRUTH.json</code>
          <span class="pkg-use">结构化攻击标注(步骤 / 事件 / 采集窗口),机读版</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">RECORD_GROUND_TRUTH.jsonl</code>
          <span class="pkg-use">逐条日志级标注(每行一条日志的归属与标签),用于检测算法训练评估</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">ARTIFACTS_MANIFEST.json</code>
          <span class="pkg-use">攻击样本清单(文件名 / 哈希 / 用途说明)</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">.quality-generation.json</code>
          <span class="pkg-use">数据生成元数据(生成时间、观测范围等)</span>
        </div>
        <div class="pkg-row">
          <code class="pkg-name">scenario/</code>
          <span class="pkg-use">剧本定义与来源研究:scenario.yaml(环境/攻击链/事件定义)、research.md(原始 APT 报告的事实矩阵与选材依据)</span>
        </div>
        <div class="pkg-row" v-if="p.defenseFile">
          <code class="pkg-name">defense/</code>
          <span class="pkg-use">防御侧行为告警数据(针对本剧本的防御检测告警序列)</span>
        </div>
      </div>
    </section>

    <!-- 申请下载对话框 -->
    <el-dialog :title="'申请下载:' + (p ? p.threatGroup : '')" :visible.sync="applyVisible" width="35%">
      <div class="dialog-tip">
        该剧本数据仅供学术研究和非商业用途使用。请填写以下信息,我们将在 48 小时内通过邮件回复开通下载。
      </div>
      <el-form :model="applyForm" label-width="100px">
        <el-form-item label="姓名" required>
          <el-input v-model="applyForm.name" placeholder="请输入姓名"></el-input>
        </el-form-item>
        <el-form-item label="邮箱" required>
          <el-input v-model="applyForm.email" placeholder="your.email@example.com"></el-input>
        </el-form-item>
        <el-form-item label="研究目的" required>
          <el-input type="textarea" :rows="3" v-model="applyForm.reason" placeholder="请简述研究目的与用途"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="applyVisible = false">取 消</el-button>
        <el-button type="primary" @click="submitApply">提交申请</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import request from '@/utils/request'
import { groupZh } from '@/utils/groups'

export default {
  name: 'PlaybookDetail',
  data() {
    return {
      p: null,
      steps: [],
      events: [],
      applyVisible: false,
      applyForm: { name: '', email: '', reason: '' }
    }
  },
  computed: {
    groupName() {
      return groupZh(this.p && this.p.threatGroup)
    },
    sizeText() {
      if (!this.p) return ''
      const mb = this.p.dataSizeMb || 0
      return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : mb + ' MB'
    }
  },
  created() {
    this.load()
  },
  methods: {
    load() {
      request.get('/playbook/selectById', { params: { id: this.$route.params.id } }).then(res => {
        if (res.code === '200') {
          this.p = res.data.playbook
          this.steps = res.data.steps || []
          this.events = res.data.events || []
        } else {
          this.$message.error(res.msg)
        }
      })
    },
    parseJson(s) {
      if (!s) return []
      try { return JSON.parse(s) } catch (e) { return [] }
    },
    download() {
      const user = localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')) : {}
      window.open(`/api/playbook/download?id=${this.p.id}&token=${user.token || ''}`)
      setTimeout(() => this.load(), 1500)
    },
    openApply() {
      const user = localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')) : {}
      this.applyForm.name = user.userName || ''
      this.applyVisible = true
    },
    submitApply() {
      if (!this.applyForm.name.trim()) return this.$message.error('请输入姓名')
      if (!this.applyForm.email.trim()) return this.$message.error('请输入邮箱')
      if (!this.applyForm.reason.trim()) return this.$message.error('请输入研究目的')
      request.post('/playbook/apply', {
        playbookCode: this.p.code,
        userName: this.applyForm.name,
        email: this.applyForm.email,
        reason: this.applyForm.reason
      }).then(res => {
        if (res.code === '200') {
          this.$message.success('申请提交成功!我们将在48小时内通过邮件回复您。')
          this.applyVisible = false
        } else {
          this.$message.error(res.msg)
        }
      })
    }
  }
}
</script>

<style scoped>
.playbook-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.pb-back {
  display: flex;
}
.pb-hero {
  padding: 22px 24px 18px;
}
.pb-hero-main {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 14px;
}
.pb-hero-kicker {
  font-size: 12px;
  font-weight: 700;
  color: #226ee8;
  letter-spacing: 2px;
}
.pb-hero-name {
  margin: 6px 0 0;
  font-size: 24px;
  font-weight: 800;
  letter-spacing: 0.5px;
  color: #10243b;
}
.pb-hero-sub {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  font-size: 12.5px;
  color: #71859a;
}
.pb-hero-code {
  font-family: Consolas, monospace;
  color: #1765c8;
}
.pb-hero-dot {
  color: #a8b8c8;
}
.pb-hero-divider {
  height: 1px;
  background: linear-gradient(90deg, rgba(34, 110, 232, 0.35), rgba(6, 148, 180, 0.2), transparent);
  margin: 14px 0;
}
.pb-hero-actions {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px dashed rgba(34, 110, 232, 0.18);
  flex-wrap: wrap;
}
.pb-ready-badge {
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 999px;
  background: rgba(6, 148, 180, 0.12);
  color: #05708c;
  border: 1px solid rgba(6, 148, 180, 0.4);
  font-weight: 600;
}
.pb-lock-badge {
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 999px;
  background: rgba(240, 160, 30, 0.12);
  color: #b06a00;
  border: 1px solid rgba(240, 160, 30, 0.4);
  font-weight: 600;
}
.pb-hero-desc {
  margin: 0;
  font-size: 14px;
  line-height: 1.9;
  color: #42586e;
}
.pb-stat-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 10px;
  margin-top: 16px;
}
.pb-stat {
  border: 1px solid rgba(34, 110, 232, 0.16);
  border-radius: 10px;
  padding: 10px 8px;
  text-align: center;
  background: rgba(34, 110, 232, 0.04);
}
.pb-stat b {
  display: block;
  font-size: 20px;
  color: #226ee8;
}
.pb-stat span {
  font-size: 11px;
  color: #71859a;
}
.pb-steps {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px 18px 16px;
}
.pb-step {
  display: flex;
  gap: 14px;
  border: 1px solid rgba(34, 110, 232, 0.14);
  border-radius: 12px;
  padding: 12px 14px;
  background: linear-gradient(90deg, rgba(34, 110, 232, 0.05), rgba(6, 148, 180, 0.02));
}
.pb-step-no {
  flex: none;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: linear-gradient(135deg, #226ee8, #0694b4);
  color: #fff;
  font-weight: 700;
  font-size: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.pb-step-main {
  flex: 1;
  min-width: 0;
}
.pb-step-activity {
  margin: 0 0 6px;
  font-size: 13.5px;
  font-weight: 600;
  color: #10243b;
  line-height: 1.6;
}
.pb-step-meta {
  margin: 0 0 6px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.pb-step-actor {
  font-size: 11.5px;
  color: #71859a;
}
.pb-tactic {
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 999px;
  background: rgba(34, 110, 232, 0.1);
  color: #1765c8;
  border: 1px solid rgba(34, 110, 232, 0.3);
  font-weight: 600;
}
.pb-evtype {
  font-size: 10.5px;
  padding: 1px 8px;
  border-radius: 999px;
  background: rgba(80, 101, 124, 0.08);
  color: #50657c;
  border: 1px solid rgba(80, 101, 124, 0.2);
}
.pb-tech-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.pb-tech {
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid rgba(6, 148, 180, 0.35);
  background: rgba(6, 148, 180, 0.07);
  color: #05708c;
  font-family: Consolas, monospace;
}
.pb-empty {
  color: #71859a;
  font-size: 13px;
}
.pkg-tip {
  margin: 14px 18px 0;
  font-size: 12.5px;
  color: #71859a;
}
.pkg-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 12px 18px 16px;
}
.pkg-row {
  display: flex;
  gap: 14px;
  align-items: baseline;
  border: 1px solid rgba(34, 110, 232, 0.14);
  border-radius: 10px;
  padding: 9px 14px;
  background: rgba(34, 110, 232, 0.03);
}
.pkg-name {
  flex: none;
  width: 220px;
  font-size: 12px;
  color: #1765c8;
  font-family: Consolas, monospace;
  word-break: break-all;
}
.pkg-use {
  font-size: 12px;
  color: #50657c;
  line-height: 1.6;
}
.pb-download-count {
  font-size: 12px;
  color: #71859a;
}
.pb-download-tip {
  font-size: 12px;
  color: #b06a00;
}
.dialog-tip {
  font-size: 12.5px;
  color: #50657c;
  line-height: 1.7;
  margin-bottom: 14px;
}
</style>
