<template>
  <div class="leaderboard-container">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-content">
        <h1 class="hero-title">APT流量检测排行榜</h1>
        <p class="hero-subtitle">权威的APT流量检测模型评测榜单</p>
      </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
      <!-- Section Header -->
      <div class="section-header">
        <h2 class="section-title">排行榜</h2>
        <p class="section-subtitle">基于ZAPT数据集的模型性能评测</p>
      </div>

      <!-- Framework Highlight -->
      <el-card class="framework-card" shadow="hover">
        <div class="framework-content">
          <div class="framework-icon">🚀</div>
          <div class="framework-text">
            <h4>统一的特征提取与评测框架</h4>
            <p>我们设计了统一的特征提取框架和评测标准，您可以直接使用我们的库在ZAPT数据集上进行模型设计和评测，确保公平、一致的性能对比。</p>
            <el-button type="primary" icon="el-icon-link" @click="openFramework" style="background-color: #4a90e2; border-color: #4a90e2;">
              📦 访问评测框架
            </el-button>
          </div>
        </div>
      </el-card>

      <!-- Tabs -->
      <el-tabs v-model="activeTab" type="border-card" class="leaderboard-tabs">
        <el-tab-pane label="开源榜单" name="opensource">
          <!-- Open Source Leaderboard -->
          <el-card shadow="never" class="leaderboard-card">
            <el-table
                :data="openSourceModels"
                stripe
                :header-cell-style="{
                  background: '#4a90e2',
                  color: 'white',
                  fontWeight: '600'
                }"
                style="width: 100%"
            >
              <el-table-column label="排名" width="80" align="center">
                <template slot-scope="{ row }">
                  <el-tag :type="getRankType(row.rank)" effect="dark">
                    {{ row.rank }}
                  </el-tag>
                </template>
              </el-table-column>

              <el-table-column label="模型名称" min-width="200">
                <template slot-scope="{ row }">
                  <div class="model-info">
                    <div class="model-name">{{ row.name }}</div>
                    <div class="model-org">{{ row.organization }}</div>
                  </div>
                </template>
              </el-table-column>

              <el-table-column prop="accuracy" label="准确率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.accuracy }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="precision" label="精确率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.precision }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="recall" label="召回率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.recall }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="f1" label="F1分数" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.f1 }}</div>
                </template>
              </el-table-column>

              <el-table-column label="代码链接" width="150" align="center">
                <template slot-scope="{ row }">
                  <el-button
                      type="primary"
                      icon="el-icon-link"
                      size="small"
                      @click="openGithub(row.github)"
                      style="background-color: #4a90e2; border-color: #4a90e2;"
                  >
                    GitHub
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-card>

          <!-- Submission Info -->
          <el-alert
              title="📢 提交您的模型"
              type="info"
              :closable="false"
              class="submission-alert"
          >
            <p>
              如果您开发了基于ZAPT数据集的APT检测模型，欢迎提交到开源榜单！请在GitHub上开源您的代码，并发送邮件至
              <strong>axuhongbo@126.com</strong> 附上模型说明、性能指标和代码链接。
            </p>
          </el-alert>
        </el-tab-pane>

        <el-tab-pane label="闭源榜单" name="closedsource">
          <!-- Closed Source Leaderboard -->
          <el-card shadow="never" class="leaderboard-card">
            <el-table
                :data="closedSourceModels"
                stripe
                :header-cell-style="{
                  background: '#4a90e2',
                  color: 'white',
                  fontWeight: '600'
                }"
                style="width: 100%"
            >
              <el-table-column label="排名" width="80" align="center">
                <template slot-scope="{ row }">
                  <el-tag :type="getRankType(row.rank)" effect="dark">
                    {{ row.rank }}
                  </el-tag>
                </template>
              </el-table-column>

              <el-table-column label="模型名称" min-width="200">
                <template slot-scope="{ row }">
                  <div class="model-info">
                    <div class="model-name">{{ row.name }}</div>
                    <div class="model-org">{{ row.organization }}</div>
                  </div>
                </template>
              </el-table-column>

              <el-table-column prop="accuracy" label="准确率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.accuracy }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="precision" label="精确率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.precision }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="recall" label="召回率" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.recall }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="f1" label="F1分数" width="100" align="center">
                <template slot-scope="{ row }">
                  <div class="metric-value">{{ row.f1 }}</div>
                </template>
              </el-table-column>

              <el-table-column prop="institution" label="机构" width="150" align="center"></el-table-column>
            </el-table>
          </el-card>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Leaderboard',
  data() {
    return {
      activeTab: 'opensource',
      openSourceModels: [
        {
          id: 1,
          rank: 1,
          name: 'APTSniffer',
          organization: '清华大学',
          accuracy: '98.2%',
          precision: '97.5%',
          recall: '98.8%',
          f1: '98.1%',
          github: 'https://github.com/yourname/aptsniffer',
          institution: 'THU'
        },
        {
          id: 2,
          rank: 2,
          name: 'ZAPT-Detector',
          organization: '麻省理工学院',
          accuracy: '96.8%',
          precision: '96.2%',
          recall: '97.3%',
          f1: '96.7%',
          github: 'https://github.com/mit/zapt-detector',
          institution: 'MIT'
        },
        {
          id: 3,
          rank: 3,
          name: 'Enterprise-APT-Detector',
          organization: '国家互联网应急响应中心',
          accuracy: '97.5%',
          precision: '96.8%',
          recall: '98.1%',
          f1: '97.4%',
          github: 'https://github.com/cncert/enterprise-apt-detector',
          institution: 'CNCERT'
        },
        {
          id: 4,
          rank: 4,
          name: 'AdvancedThreatNet',
          organization: '信息工程大学',
          accuracy: '95.9%',
          precision: '95.2%',
          recall: '96.5%',
          f1: '95.8%',
          github: 'https://github.com/iie/advancedthreatnet',
          institution: 'IIE'
        },
        {
          id: 5,
          rank: 5,
          name: 'IntelliDefense-Pro',
          organization: '清华大学',
          accuracy: '94.8%',
          precision: '94.1%',
          recall: '95.4%',
          f1: '94.7%',
          github: 'https://github.com/thu/intellidefense-pro',
          institution: 'Tsinghua'
        }
      ],
      closedSourceModels: [
        {
          id: 1,
          rank: 1,
          name: 'DeepAPT',
          organization: 'Google Research',
          accuracy: '99.1%',
          precision: '98.7%',
          recall: '99.4%',
          f1: '99.0%',
          institution: 'Google'
        },
        {
          id: 2,
          rank: 2,
          name: 'NeuralThreat',
          organization: 'Microsoft Security',
          accuracy: '98.7%',
          precision: '98.3%',
          recall: '98.9%',
          f1: '98.6%',
          institution: 'Microsoft'
        },
        {
          id: 3,
          rank: 3,
          name: 'CyberShield-X',
          organization: 'IBM Research',
          accuracy: '97.9%',
          precision: '97.4%',
          recall: '98.2%',
          f1: '97.8%',
          institution: 'IBM'
        }
      ]
    }
  },
  methods: {
    getRankType(rank) {
      const rankTypes = {
        1: 'warning', // 金色
        2: 'info',    // 银色
        3: ''         // 铜色
      }
      return rankTypes[rank] || 'success'
    },
    openFramework() {
      window.open('https://github.com/linwhitehat/zapt-benchmark', '_blank')
    },
    openGithub(url) {
      window.open(url, '_blank')
    }
  }
}
</script>

<style scoped>
.leaderboard-container {
  min-height: 100vh;
  background: white;
}

.hero-section {
  background: linear-gradient(135deg, #4a90e2 0%, #764ba2 100%);
  color: white;
  padding: 100px 20px 80px;
  text-align: center;
}

.hero-content {
  max-width: 800px;
  margin: 0 auto;
}

.hero-title {
  font-size: 3.5rem;
  font-weight: 800;
  margin-bottom: 20px;
  background: linear-gradient(45deg, #fff, #e0e7ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hero-subtitle {
  font-size: 1.5rem;
  opacity: 0.9;
  max-width: 600px;
  margin: 0 auto;
}

.main-content {
  max-width: 1200px;
  margin: -40px auto 0;
  padding: 40px 20px 60px;
  position: relative;
  z-index: 10;
}

.section-header {
  text-align: center;
  margin-bottom: 40px;
}

.section-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #2c3e50;
  margin-bottom: 15px;
}

.section-subtitle {
  font-size: 1.2rem;
  color: #7f8c8d;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.framework-card {
  border: none;
  border-radius: 16px;
  margin-bottom: 40px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
}

.framework-content {
  display: flex;
  align-items: flex-start;
  gap: 20px;
}

.framework-icon {
  font-size: 3rem;
  flex-shrink: 0;
  color: #4a90e2;
}

.framework-text {
  flex: 1;
}

.framework-text h4 {
  font-size: 1.3rem;
  margin-bottom: 15px;
  color: #2c3e50;
}

.framework-text p {
  color: #2c3e50;
  line-height: 1.8;
  margin-bottom: 15px;
}

.leaderboard-tabs {
  margin-bottom: 30px;
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}

.leaderboard-card {
  border: none;
  border-radius: 8px;
  overflow: hidden;
}

.model-info {
  text-align: left;
}

.model-name {
  font-weight: 600;
  color: #2c3e50;
  font-size: 1.05rem;
  margin-bottom: 4px;
}

.model-org {
  color: #7f8c8d;
  font-size: 0.9rem;
}

.metric-value {
  font-size: 1.2rem;
  font-weight: 700;
  color: #4a90e2;
}

.submission-alert {
  margin-top: 30px;
  border-radius: 8px;
  border-color: #bfdbfe;
  background-color: #dbeafe;
}

.submission-alert p {
  margin: 0;
  line-height: 1.7;
  color: #2c3e50;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .hero-title {
    font-size: 2rem;
  }

  .hero-subtitle {
    font-size: 1.2rem;
  }

  .section-title {
    font-size: 2rem;
  }

  .framework-content {
    flex-direction: column;
    text-align: center;
  }

  .framework-icon {
    margin-bottom: 15px;
  }
}
</style>