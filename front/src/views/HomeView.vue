<template>
  <div class="home-page">
    <!-- 数据检索与生成入口 -->
    <section class="cc-panel home-search">
      <div class="hs-row">
        <el-input v-model="searchKeyword" size="small" clearable placeholder="如:鱼叉邮件 / 蜻蜓 / 拉撒路" @keyup.enter.native="doSearch" style="flex:1;max-width:320px"></el-input>
        <el-select v-if="isLoggedIn" v-model="searchGroup" size="small" clearable placeholder="全部组织" style="width:210px">
          <el-option v-for="(cnt, g) in groups" :key="g" :label="`${groupZh(g)} (${cnt})`" :value="g"></el-option>
        </el-select>
        <button class="cc-primary-button hs-search-btn" type="button" @click="doSearch">
          <svg viewBox="0 0 24 24" width="14" height="14"><circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="2"/><path d="m20 20-3.5-3.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          检索数据集
        </button>
      </div>
      <div class="hs-row hs-gen-row">
        <button class="hs-gen-button" type="button" :class="{ open: genOpen }" @click="openGen">
          {{ genOpen ? '收起生成表单' : '没有找到你想要的数据集?点击这里生成你想要的数据' }}
          <svg viewBox="0 0 24 24" width="13" height="13"><path d="M5 12h14m-6-6 6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
      </div>

      <!-- 展开式生成表单 -->
      <div v-if="genOpen" class="hs-gen-form">
        <div class="hs-gen-form-head">
          <b>生成你想要的数据</b>
          <span>提交后我们将分析参考报告并生成对应的攻击链剧本与多源日志</span>
        </div>
        <el-form :model="genForm" label-width="90px">
          <el-form-item label="生成事件" required>
            <el-input type="textarea" :autosize="{ minRows: 8, maxRows: 24 }" v-model="genForm.events"
              placeholder="详细描述你想生成的攻击事件/场景,可按攻击链步骤展开描述(支持长文本,如数千字的完整攻击剧本):
如:APT29 以鱼叉邮件投递,利用 CVE 漏洞获取初始访问后横向移动至域控并窃取凭据,最终经加密通道外传数据……"></el-input>
          </el-form-item>
          <el-form-item label="参考来源">
            <el-upload
              :action="'/api/generation/upload'"
              :headers="uploadHeaders"
              :limit="1"
              :file-list="genFileList"
              accept=".pdf"
              :before-upload="beforeGenUpload"
              :on-success="onGenUploadOk"
              :on-error="onGenUploadErr"
              :on-remove="onGenUploadRemove">
              <el-button size="small" type="primary" plain>上传 APT 报告(PDF)</el-button>
              <span class="hs-upload-tip">目前仅支持 APT 报告(PDF)的分析;流量 / 样本:待开发</span>
            </el-upload>
          </el-form-item>
          <el-form-item label="备注">
            <el-input type="textarea" :autosize="{ minRows: 2, maxRows: 6 }" v-model="genForm.remark" placeholder="其他说明(可选)"></el-input>
          </el-form-item>
          <el-form-item>
            <button class="cc-primary-button" type="button" @click="submitGen">提交生成申请</button>
            <button class="cc-text-button" type="button" @click="closeGen">收起</button>
          </el-form-item>
        </el-form>
      </div>
    </section>

    <!-- 当前数据资产统计 -->
    <section class="cc-panel">
      <div class="cc-section-head">
        <div>
          <span class="cc-section-kicker">DATA ASSETS</span>
          <h1>当前数据资产统计</h1>
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-card">
          <span class="stat-icon icon-blue">
            <svg viewBox="0 0 24 24" focusable="false"><path d="M5 4h14v16H5z" fill="currentColor" opacity=".14"/><path d="M8 8h8M8 12h8M8 16h5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          </span>
          <span class="stat-body">
            <span class="stat-label">日志数据规模</span>
            <span class="dual-stat"><strong>2076.6万</strong><em>总计</em><strong>344.7万</strong><em>去重</em></span>
            <span class="stat-note">黑 11,720 · 白 20,754,280 · 对标 DARPA E3/E5</span>
          </span>
        </div>

        <div class="stat-card">
          <span class="stat-icon icon-red">
            <svg viewBox="0 0 24 24" focusable="false"><path d="M12 3 4 7v10l8 4 8-4V7l-8-4Z" fill="currentColor" opacity=".16"/><path d="M12 3v18M4 7l8 4 8-4M7.5 15l4.5 2.2 4.5-2.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
          </span>
          <span class="stat-body">
            <span class="stat-label">攻击事件</span>
            <strong>74</strong>
            <span class="stat-note">DARPA E3:13 · E5:12 · 平均 9.3 步 / 最长 29 步</span>
          </span>
        </div>

        <div class="stat-card">
          <span class="stat-icon icon-teal">
            <svg viewBox="0 0 24 24" focusable="false"><path d="m12 2 8 4.5v9L12 20 4 15.5v-9L12 2Z" fill="currentColor" opacity=".18"/><path d="M12 2v8l8-3.5M12 10 4 6.5M12 10v10" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
          </span>
          <span class="stat-body">
            <span class="stat-label">ATT&CK 技战术</span>
            <span class="dual-stat"><strong>15</strong><em>战术</em><strong>104</strong><em>技术</em></span>
            <span class="stat-note">战术全覆盖 15/15 · 技术 104/195 · TTP 变种最高 66</span>
          </span>
        </div>

        <div class="stat-card">
          <span class="stat-icon icon-amber">
            <svg viewBox="0 0 24 24" focusable="false"><path d="M12 3 21 8v8l-9 5-9-5V8l9-5Z" fill="currentColor" opacity=".18"/><path d="M12 3v18M3 8l9 5 9-5M3 16l9-5 9 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
          </span>
          <span class="stat-body">
            <span class="stat-label">攻防博弈数据</span>
            <span class="dual-stat"><strong>139</strong><em>恶意样本</em><strong>40</strong><em>缓解措施</em></span>
            <span class="stat-note">多轮攻防博弈 · 防御侧 MITRE 措施覆盖 40/44</span>
          </span>
        </div>
      </div>
    </section>

    <!-- 多维评估对比可视化 -->
    <section class="cc-panel">
      <div class="cc-section-head">
        <div>
          <span class="cc-section-kicker">EVALUATION</span>
          <h2>多维评估对比可视化</h2>
        </div>
        <span class="head-legend">
          <i class="dot dot-e3"></i>DARPA E3
          <i class="dot dot-e5"></i>DARPA E5
          <i class="dot dot-ours"></i>数字弈境
        </span>
      </div>

      <div class="chart-grid">
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>日志规模对比(对数刻度)</h3></div>
          <div class="chart-panel-canvas"><div id="logScaleChart" class="echart-box"></div></div>
        </div>
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>覆盖范围对比(TA / TTP / 缓解措施)</h3></div>
          <div class="chart-panel-canvas"><div id="coverageChart" class="echart-box"></div></div>
        </div>
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>攻击步数对比</h3></div>
          <div class="chart-panel-canvas"><div id="stepsChart" class="echart-box"></div></div>
        </div>
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>TTP 变种数对比</h3></div>
          <div class="chart-panel-canvas"><div id="variantChart" class="echart-box"></div></div>
        </div>
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>攻击事件与恶意样本数</h3></div>
          <div class="chart-panel-canvas"><div id="entityChart" class="echart-box"></div></div>
        </div>
        <div class="chart-panel">
          <div class="chart-panel-head"><h3>数据真实度(合成与真实数据相似度)</h3></div>
          <div class="chart-panel-canvas"><div id="fidelityChart" class="echart-box"></div></div>
        </div>
      </div>
    </section>

  </div>
</template>

<script>
import * as echarts from 'echarts';
import request from '@/utils/request'
import { groupZh } from '@/utils/groups'

const SERIES_COLORS = { e3: '#8ba0b8', e5: '#226ee8', ours: '#0694b4' };
const TEXT = '#50657c';
const AXIS = '#71859a';
const SPLIT = 'rgba(50, 91, 135, .12)';

export default {
  name: 'HomeView',
  data() {
    return {
      searchKeyword: '',
      searchGroup: '',
      groups: {},
      genOpen: false,
      genForm: { events: '', sourceFile: '', remark: '' },
      genFileList: []
    }
  },
  computed: {
    isLoggedIn() {
      const u = localStorage.getItem('user')
      return !!(u && JSON.parse(u).token)
    },
    uploadHeaders() {
      const u = localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')) : {}
      return { token: u.token || '' }
    }
  },
  mounted() {
    if (this.isLoggedIn) {
      request.get('/playbook/groups').then(res => {
        if (res.code === '200') this.groups = res.data || {}
      })
    }
    this.chartInstances = [];
    this.$nextTick(() => {
      this.initLogScaleChart();
      this.initCoverageChart();
      this.initStepsChart();
      this.initVariantChart();
      this.initEntityChart();
      this.initFidelityChart();
    });
    this.handleResize = () => {
      this.chartInstances.forEach(c => c.resize());
    };
    window.addEventListener('resize', this.handleResize);
  },
  beforeDestroy() {
    window.removeEventListener('resize', this.handleResize);
    this.chartInstances.forEach(c => c.dispose());
  },
  methods: {
    groupZh,
    doSearch() {
      this.$router.push({ path: '/datasets', query: {
        keyword: this.searchKeyword.trim() || undefined,
        group: this.searchGroup || undefined
      }}).catch(() => {})
    },
    openGen() {
      if (!this.isLoggedIn) {
        this.$message.warning('请先登录后再提交生成申请')
        this.$router.push('/login').catch(() => {})
        return
      }
      this.genOpen = !this.genOpen
    },
    closeGen() {
      this.genOpen = false
      this.resetGenForm()
    },
    beforeGenUpload(file) {
      if (!/\.pdf$/i.test(file.name)) {
        this.$message.error('目前仅支持 APT 报告(PDF)格式,流量/样本待开发')
        return false
      }
      return true
    },
    onGenUploadOk(res, file) {
      if (res.code === '200') {
        this.genForm.sourceFile = res.data
        this.genFileList = [{ name: file.name }]
      } else {
        this.$message.error(res.msg || '上传失败')
      }
    },
    onGenUploadErr() {
      this.$message.error('上传失败,请重试')
    },
    onGenUploadRemove() {
      this.genForm.sourceFile = ''
      this.genFileList = []
    },
    resetGenForm() {
      this.genForm = { events: '', sourceFile: '', remark: '' }
      this.genFileList = []
    },
    submitGen() {
      if (!this.genForm.events.trim()) return this.$message.error('请填写要生成的事件')
      request.post('/generation/submit', {
        genEvents: this.genForm.events,
        sourceFile: this.genForm.sourceFile,
        remark: this.genForm.remark
      }).then(res => {
        if (res.code === '200') {
          this.$message.success('生成申请已提交,我们将分析报告并生成对应数据')
          this.closeGen()
        } else {
          this.$message.error(res.msg)
        }
      })
    },

    axis(extra) {
      return Object.assign({
        axisLine: { lineStyle: { color: AXIS } },
        axisLabel: { color: TEXT },
        splitLine: { lineStyle: { color: SPLIT } }
      }, extra || {});
    },

    catAxis(data, extra) {
      return Object.assign({
        type: 'category', data,
        axisLine: { lineStyle: { color: AXIS } },
        axisLabel: { color: TEXT }
      }, extra || {});
    },

    makeChart(domId, option) {
      const chartDom = document.getElementById(domId);
      if (!chartDom) return;
      const chart = echarts.init(chartDom);
      chart.setOption(Object.assign({ textStyle: { color: TEXT } }, option));
      this.chartInstances.push(chart);
    },

    bar(name, data, color, bold) {
      return {
        name, type: 'bar', data,
        itemStyle: { color, borderRadius: [4, 4, 0, 0] },
        label: {
          show: true, position: 'top', fontSize: 10,
          color: bold ? '#047a95' : TEXT,
          fontWeight: bold ? 'bold' : 'normal',
          formatter: p => p.value >= 10000
            ? (p.value / 10000).toFixed(p.value >= 1000000 ? 0 : 1).replace(/\.0$/, '') + '万'
            : p.value.toLocaleString()
        }
      };
    },

    initLogScaleChart() {
      this.makeChart('logScaleChart', {
        tooltip: {
          trigger: 'axis', axisPointer: { type: 'shadow' },
          formatter: (params) => {
            let html = params[0].name + '<br/>';
            params.forEach(p => {
              html += p.marker + p.seriesName + ': ' + Number(p.value).toLocaleString() + ' 条<br/>';
            });
            return html;
          }
        },
        legend: { top: 0, textStyle: { color: TEXT } },
        grid: { left: '2%', right: '3%', bottom: '3%', top: '16%', containLabel: true },
        xAxis: this.catAxis(['黑日志', '白日志', '总计', '去重后']),
        yAxis: this.axis({
          type: 'log', name: '条数(对数刻度)', nameTextStyle: { color: TEXT },
          axisLabel: { color: TEXT, formatter: v => v >= 10000 ? (v / 10000) + '万' : v.toLocaleString() }
        }),
        series: [
          this.bar('DARPA TC E3', [235, 2182865, 2183100, 22049], SERIES_COLORS.e3),
          this.bar('DARPA TC E5', [247, 15092914, 15093161, 199229], SERIES_COLORS.e5),
          this.bar('数字弈境', [11720, 20754280, 20766000, 3447496], SERIES_COLORS.ours, true)
        ]
      });
    },

    initCoverageChart() {
      const totals = [15, 195, 44];
      const raw = {
        'DARPA TC E3': [8, 12, 27],
        'DARPA TC E5': [8, 10, 26],
        '数字弈境': [15, 104, 40]
      };
      const mk = (name, color, bold) => {
        const s = this.bar(name, raw[name].map((v, i) => +(v / totals[i] * 100).toFixed(1)), color, bold);
        s.label.formatter = p => raw[name][p.dataIndex] + '/' + totals[p.dataIndex];
        return s;
      };
      this.makeChart('coverageChart', {
        tooltip: {
          trigger: 'axis', axisPointer: { type: 'shadow' },
          formatter: (params) => {
            let html = params[0].name + '<br/>';
            params.forEach(p => {
              html += p.marker + p.seriesName + ': ' + raw[p.seriesName][p.dataIndex] + '/' + totals[p.dataIndex] + ' (' + p.value + '%)<br/>';
            });
            return html;
          }
        },
        legend: { top: 0, textStyle: { color: TEXT } },
        grid: { left: '2%', right: '3%', bottom: '3%', top: '16%', containLabel: true },
        xAxis: this.catAxis(['TA数(战术)\n总15', 'TTP数(技术)\n总195', '防御侧缓解措施\n总44'], { axisLabel: { color: TEXT, interval: 0, fontSize: 10 } }),
        yAxis: this.axis({ type: 'value', max: 100, axisLabel: { color: TEXT, formatter: '{value}%' } }),
        series: [
          mk('DARPA TC E3', SERIES_COLORS.e3, false),
          mk('DARPA TC E5', SERIES_COLORS.e5, false),
          mk('数字弈境', SERIES_COLORS.ours, true)
        ]
      });
    },

    initStepsChart() {
      this.makeChart('stepsChart', {
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        legend: { top: 0, textStyle: { color: TEXT } },
        grid: { left: '2%', right: '3%', bottom: '3%', top: '16%', containLabel: true },
        xAxis: this.catAxis(['最小步数', '平均步数', '最大步数']),
        yAxis: this.axis({ type: 'value' }),
        series: [
          this.bar('DARPA TC E3', [2, 5.6, 10], SERIES_COLORS.e3),
          this.bar('DARPA TC E5', [2, 5.2, 8], SERIES_COLORS.e5),
          this.bar('数字弈境', [5, 9.3, 29], SERIES_COLORS.ours, true)
        ]
      });
    },

    initVariantChart() {
      this.makeChart('variantChart', {
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        legend: { top: 0, textStyle: { color: TEXT } },
        grid: { left: '2%', right: '3%', bottom: '3%', top: '16%', containLabel: true },
        xAxis: this.catAxis(['最小变种数', '平均变种数', '最大变种数']),
        yAxis: this.axis({ type: 'value' }),
        series: [
          this.bar('DARPA TC E3', [1, 3.5, 7], SERIES_COLORS.e3),
          this.bar('DARPA TC E5', [1, 3.6, 5], SERIES_COLORS.e5),
          this.bar('数字弈境', [1, 4.1, 66], SERIES_COLORS.ours, true)
        ]
      });
    },

    initEntityChart() {
      this.makeChart('entityChart', {
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        legend: { top: 0, textStyle: { color: TEXT } },
        grid: { left: '2%', right: '3%', bottom: '3%', top: '16%', containLabel: true },
        xAxis: this.catAxis(['攻击事件数', '攻击使用的恶意样本数'], { axisLabel: { color: TEXT, interval: 0 } }),
        yAxis: this.axis({ type: 'value' }),
        series: [
          this.bar('DARPA TC E3', [13, 18], SERIES_COLORS.e3),
          this.bar('DARPA TC E5', [12, 18], SERIES_COLORS.e5),
          this.bar('数字弈境', [74, 139], SERIES_COLORS.ours, true)
        ]
      });
    },

    initFidelityChart() {
      const mkGauge = (name, value, color, center) => ({
        type: 'gauge',
        center,
        radius: '82%',
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        axisLine: {
          lineStyle: {
            width: 12,
            color: [[value / 100, color], [1, '#e3ecf5']]
          }
        },
        pointer: { itemStyle: { color: color }, length: '60%', width: 4 },
        axisTick: { distance: -12, length: 4, lineStyle: { color: '#fff' } },
        splitLine: { distance: -12, length: 12, lineStyle: { color: '#fff', width: 2 } },
        axisLabel: { distance: -30, color: AXIS, fontSize: 9 },
        title: { offsetCenter: [0, '62%'], fontSize: 12, color: TEXT, fontWeight: name === '数字弈境' ? 'bold' : 'normal' },
        detail: {
          offsetCenter: [0, '32%'],
          formatter: '{value}%',
          color: color,
          fontSize: 18,
          fontWeight: 'bold'
        },
        data: [{ value: value, name: name }]
      });
      this.makeChart('fidelityChart', {
        series: [
          mkGauge('DARPA TC E3', 100, SERIES_COLORS.e3, ['17%', '58%']),
          mkGauge('DARPA TC E5', 100, SERIES_COLORS.e5, ['50%', '58%']),
          mkGauge('数字弈境', 92.54, SERIES_COLORS.ours, ['83%', '58%'])
        ]
      });
    }
  }
}
</script>

<style scoped>
.home-page {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* ---------- 统计卡 ---------- */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  padding: 12px 14px 14px;
}

.stat-card {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr);
  gap: 10px;
  padding: 11px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: var(--panel-soft);
}

.stat-icon {
  width: 38px;
  height: 38px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: #ffffff;
}

.stat-icon svg {
  width: 22px;
  height: 22px;
}

.stat-icon.icon-blue { color: var(--blue); }
.stat-icon.icon-red { color: var(--red); }
.stat-icon.icon-teal { color: var(--teal); }
.stat-icon.icon-amber { color: var(--amber); }

.stat-body {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.stat-label {
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
}

.stat-body strong {
  color: var(--navy);
  font-size: 21px;
  font-weight: 850;
  line-height: 1.2;
}

.dual-stat {
  display: flex;
  align-items: baseline;
  gap: 5px;
  flex-wrap: wrap;
}

.dual-stat em {
  color: var(--faint);
  font-size: 11px;
  font-style: normal;
  margin-right: 6px;
}

.stat-note {
  color: var(--faint);
  font-size: 11px;
}

/* ---------- 图表面板 ---------- */
.head-legend {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--muted);
  font-size: 12px;
}

.dot {
  display: inline-block;
  width: 9px;
  height: 9px;
  border-radius: 50%;
}

.dot-e3 { background: #8ba0b8; margin-left: 6px; }
.dot-e5 { background: #226ee8; margin-left: 6px; }
.dot-ours { background: #0694b4; margin-left: 6px; }

.chart-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
  padding: 12px 14px 14px;
}

.chart-panel {
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: #ffffff;
  overflow: hidden;
}

.chart-panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-bottom: 1px solid var(--line-soft);
}

.chart-panel-head h3 {
  margin: 0;
  color: var(--navy);
  font-size: 13px;
  font-weight: 750;
}

.chart-panel-canvas {
  padding: 6px;
}

.echart-box {
  width: 100%;
  height: 215px;
}

/* ---------- 表格区 ---------- */

@media (max-width: 1200px) {
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
  .chart-grid { grid-template-columns: 1fr; }
}
/* 数据检索与生成入口 */
.home-search {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.hs-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.hs-search-btn {
  white-space: nowrap;
}
.hs-gen-row {
  border-top: 1px dashed rgba(34, 110, 232, 0.18);
  padding-top: 10px;
}
.hs-gen-button {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px dashed rgba(6, 148, 180, 0.45);
  background: linear-gradient(90deg, rgba(6, 148, 180, 0.07), rgba(34, 110, 232, 0.05));
  color: #047a95;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.hs-gen-button:hover {
  background: linear-gradient(90deg, rgba(6, 148, 180, 0.14), rgba(34, 110, 232, 0.1));
  border-color: rgba(6, 148, 180, 0.75);
}
.hs-gen-button.open {
  background: linear-gradient(90deg, rgba(6, 148, 180, 0.16), rgba(34, 110, 232, 0.12));
  border-color: rgba(6, 148, 180, 0.8);
}
.hs-gen-form {
  border: 1px solid rgba(6, 148, 180, 0.3);
  border-radius: 12px;
  padding: 16px 18px;
  background: linear-gradient(180deg, rgba(6, 148, 180, 0.045), rgba(34, 110, 232, 0.025));
}
.hs-gen-form-head {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-bottom: 14px;
  padding-bottom: 10px;
  border-bottom: 1px dashed rgba(6, 148, 180, 0.3);
}
.hs-gen-form-head b {
  font-size: 15px;
  color: #10243b;
}
.hs-gen-form-head span {
  font-size: 12px;
  color: #71859a;
}
.hs-upload-tip {
  margin-left: 10px;
  font-size: 12px;
  color: #a06a1b;
}
</style>
