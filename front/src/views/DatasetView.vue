<template>
  <div class="datasets-page">
    <!-- 页头 -->
    <section class="page-hero">
      <span class="hero-kicker amber">📦 数据集下载</span>
      <h1>攻击链数据集</h1>
      <p class="hero-desc">
        基于真实 APT 报告重建的 74 个攻击链剧本,每个剧本含完整攻击步骤、ATT&CK 映射与多源异构日志,可用于威胁狩猎与教学演示。
      </p>
      <div class="hero-stat-row">
        <span class="hero-stat"><b>74</b><span>攻击链剧本</span></span>
        <span class="hero-stat"><b>689</b><span>攻击步骤</span></span>
        <span class="hero-stat"><b>1021</b><span>标注黑事件</span></span>
        <span class="hero-stat"><b>104</b><span>覆盖 TTP</span></span>
        <span class="hero-stat"><b>44.9GB</b><span>多源日志</span></span>
      </div>
    </section>

    <!-- 筛选栏 -->
    <section class="cc-panel">
      <div class="filter-bar">
        <label class="filter-item">
          <span class="filter-label">关键词检索</span>
          <el-input v-model="keyword" size="small" placeholder="如:鱼叉邮件 / 蜻蜓 / 拉撒路" clearable style="width: 260px"></el-input>
        </label>
        <label class="filter-item">
          <span class="filter-label">按组织筛选</span>
          <el-select v-model="pbGroup" size="small" clearable placeholder="全部组织" style="width: 220px">
            <el-option v-for="(cnt, g) in groups" :key="g" :label="`${groupZh(g)} (${cnt})`" :value="g"></el-option>
          </el-select>
        </label>
        <span class="filter-feedback">{{ feedbackText }}</span>
        <button v-if="keyword || pbGroup" class="cc-text-button" type="button" @click="resetFilters">↺ 重置</button>
      </div>
    </section>

    <!-- 剧本卡片列表 -->
    <section class="pb-grid">
      <article v-for="p in pagedPlaybooks" :key="p.id" class="cc-panel pb-card" :class="{ 'pb-ready': p.downloadable === 1 }" @click="goPlaybook(p)">
        <div class="pb-card-top">
          <span class="pb-seq">剧本 #{{ String(p.seqNo).padStart(2, '0') }}</span>
          <span v-if="p.downloadable === 1" class="pb-badge">可下载</span>
          <span v-else class="pb-badge pb-badge-lock">需申请</span>
        </div>
        <h3 class="pb-card-name">{{ groupZh(p.threatGroup) }}</h3>
        <p class="pb-card-date">{{ p.threatGroup }}<template v-if="p.attackDate"> · {{ p.attackDate }}</template></p>
        <p class="pb-card-desc">{{ p.description }}</p>
        <div class="pb-card-stats">
          <span><b>{{ p.stepCount }}</b>步骤</span>
          <span><b>{{ p.techniqueCount }}</b>TTP</span>
          <span><b>{{ sizeText(p) }}</b></span>
        </div>
      </article>
    </section>

    <!-- 空状态 -->
    <section v-if="filteredPlaybooks.length === 0" class="cc-panel empty-panel">
      <p>没有匹配的攻击链剧本,请调整关键词或组织筛选条件。</p>
      <button class="cc-text-button" type="button" @click="resetFilters">↺ 重置筛选</button>
    </section>

    <!-- 分页 -->
    <div class="pb-pager" v-if="filteredPlaybooks.length > 0">
      <el-pagination background layout="prev, pager, next" :total="filteredPlaybooks.length" :page-size="pageSize"
                     :current-page.sync="page"></el-pagination>
    </div>
  </div>
</template>

<script>
import request from '@/utils/request'
import { groupZh } from '@/utils/groups'

export default {
  name: 'DatasetView',
  data() {
    return {
      keyword: '',
      pbGroup: '',
      playbooks: [],
      groups: {},
      page: 1,
      pageSize: 12
    }
  },
  computed: {
    filteredPlaybooks() {
      const kw = this.keyword.trim().toLowerCase()
      return this.playbooks.filter(p => {
        const groupHit = !this.pbGroup || p.threatGroup === this.pbGroup
        const kwHit = !kw ||
          p.threatGroup.toLowerCase().includes(kw) ||
          (groupZh(p.threatGroup) || '').toLowerCase().includes(kw) ||
          p.code.toLowerCase().includes(kw) ||
          (p.description || '').toLowerCase().includes(kw)
        return groupHit && kwHit
      })
    },
    pagedPlaybooks() {
      const start = (this.page - 1) * this.pageSize
      return this.filteredPlaybooks.slice(start, start + this.pageSize)
    },
    feedbackText() {
      const n = this.filteredPlaybooks.length
      if (this.keyword || this.pbGroup) return `已筛选出 ${n} / ${this.playbooks.length} 个剧本`
      return `共 ${this.playbooks.length} 个攻击链剧本,前 2 个已开放直接下载`
    }
  },
  watch: {
    keyword() { this.page = 1 },
    pbGroup() { this.page = 1 }
  },
  mounted() {
    // 接收首页检索跳转带来的筛选参数
    if (this.$route.query.keyword) this.keyword = String(this.$route.query.keyword)
    if (this.$route.query.group) this.pbGroup = String(this.$route.query.group)
    request.get('/playbook/selectPage', { params: { pageNum: 1, pageSize: 200 } }).then(res => {
      if (res.code === '200') this.playbooks = res.data.records || []
    })
    request.get('/playbook/groups').then(res => {
      if (res.code === '200') this.groups = res.data || {}
    })
  },
  methods: {
    groupZh,
    sizeText(p) {
      const mb = p.dataSizeMb || 0
      return mb >= 1024 ? (mb / 1024).toFixed(1) + 'GB' : mb + 'MB'
    },
    resetFilters() {
      this.keyword = ''
      this.pbGroup = ''
    },
    goPlaybook(p) {
      this.$router.push(`/playbook/${p.id}`)
    }
  }
}
</script>

<style scoped>
.datasets-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: center;
}
.filter-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.filter-label {
  font-size: 12.5px;
  font-weight: 600;
  color: #50657c;
  white-space: nowrap;
}
.filter-feedback {
  margin-left: auto;
  font-size: 12px;
  color: #71859a;
}
.pb-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}
.pb-card {
  padding: 14px 16px;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 6px;
  transition: box-shadow 0.2s, transform 0.2s, border-color 0.2s;
}
.pb-card:hover {
  transform: translateY(-2px);
}
.pb-card.pb-ready {
  border-color: rgba(6, 148, 180, 0.45);
}
.pb-card-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.pb-seq {
  font-weight: 700;
  color: #226ee8;
  font-size: 12px;
  letter-spacing: 0.5px;
}
.pb-badge {
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 999px;
  background: rgba(6, 148, 180, 0.12);
  color: #05708c;
  border: 1px solid rgba(6, 148, 180, 0.4);
  font-weight: 600;
}
.pb-badge-lock {
  background: rgba(240, 160, 30, 0.1);
  color: #b06a00;
  border-color: rgba(240, 160, 30, 0.35);
}
.pb-card-name {
  margin: 0;
  font-size: 16px;
  color: #10243b;
}
.pb-card-date {
  margin: 0;
  font-size: 11.5px;
  color: #71859a;
  word-break: break-all;
}
.pb-card-desc {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: #50657c;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
  min-height: 57px;
}
.pb-card-stats {
  display: flex;
  gap: 10px;
  font-size: 11px;
  color: #71859a;
}
.pb-card-stats b {
  color: #10243b;
  font-size: 13px;
  margin-right: 2px;
}
.pb-pager {
  display: flex;
  justify-content: center;
}
.empty-panel {
  text-align: center;
  padding: 30px;
  color: #71859a;
  font-size: 13px;
}
.empty-panel .cc-text-button {
  margin-top: 8px;
}
</style>
