<template>
  <div class="project-container">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-content">
        <div class="conference-badge">
          ICASSP 2025
        </div>
        <h1 class="hero-title">APTSniffer</h1>
        <h2 class="hero-subtitle">
          Detecting APT Attack Traffic Using Retrieval-Augmented Large Language Models
        </h2>
        <p class="hero-description">
          基于检索增强大语言模型的APT攻击流量检测
        </p>
      </div>
    </div>

    <!-- 核心挑战 -->
    <div class="challenge-section">
      <div class="section-header">
        <h2 class="section-title">核心挑战</h2>
        <p class="section-subtitle">Core Challenges</p>
      </div>

      <el-card class="challenge-card" shadow="hover">
        <div class="challenge-content">
          <div class="challenge-icon">🚨</div>
          <div class="challenge-text">
            <p class="challenge-description">
              由于APT流量数据短缺和加密流量混淆等问题，现有方法无法仅凭少量攻击流量样本准确识别APT流量。
            </p>
            <p class="solution-text">
              为了克服上述限制，我们提出了一种新颖的加密APT流量检测模型APTSniffer，该模型结合了大语言模型（LLM）和检索增强技术（RAG）。
            </p>
          </div>
        </div>
      </el-card>
    </div>

    <!-- 工作流程 -->
    <div class="workflow-section">
      <div class="section-header">
        <h2 class="section-title">工作流程</h2>
        <p class="section-subtitle">Workflow</p>
      </div>

      <div class="workflow-steps">
        <div v-for="(step, index) in workflowSteps" :key="step.id" class="workflow-step">
          <div class="step-number">{{ step.number }}</div>
          <div class="step-content">
            <h3 class="step-title">{{ step.title }}</h3>
            <p class="step-description">{{ step.description }}</p>
          </div>
          <div v-if="index < workflowSteps.length - 1" class="step-arrow">→</div>
        </div>
      </div>
    </div>

    <!-- 数据集统计 -->
    <div class="dataset-section">
      <div class="section-header">
        <h2 class="section-title">数据集统计</h2>
        <p class="section-subtitle">Dataset Statistics</p>
      </div>

      <div class="dataset-stats">
        <div v-for="stat in datasetStats" :key="stat.id" class="stat-item">
          <div class="stat-number">{{ stat.number }}</div>
          <div class="stat-label">{{ stat.label }}</div>
        </div>
      </div>
    </div>

    <!-- 引用信息 -->
    <div class="citation-section">
      <div class="section-header">
        <h2 class="section-title">引用信息</h2>
        <p class="section-subtitle">Citation</p>
      </div>

      <el-card class="citation-card" shadow="hover">
        <div class="citation-content">
          <p>如果您使用本论文中的数据集，请务必包含适当的引用。</p>
          <div class="citation-code">
            @inproceedings{aptsniffer2025,<br>
            &nbsp;&nbsp;title={APTSniffer: Detecting APT Attack Traffic Using Retrieval-Augmented Large Language Models},<br>
            &nbsp;&nbsp;author={Your Name and Co-authors},<br>
            &nbsp;&nbsp;booktitle={IEEE International Conference on Acoustics, Speech and Signal Processing (ICASSP)},<br>
            &nbsp;&nbsp;year={2025},<br>
            &nbsp;&nbsp;organization={IEEE}<br>
            }
          </div>
          <el-button type="primary" class="copy-button" @click="copyCitation" style="background-color: #4a90e2; border-color: #4a90e2;">
            <i class="el-icon-document-copy"></i>
            复制引用
          </el-button>
        </div>
      </el-card>
    </div>

    <!-- 页脚 -->
    <div class="footer-section">
      <div class="footer-content">
        <p>© 2025 APTSniffer Project. All rights reserved.</p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'APTSnifferProject',
  data() {
    return {
      workflowSteps: [
        {
          id: 1,
          number: '1',
          title: '特征提取',
          description: '从PCAP文件中，基于流（由IP、端口和协议的五元组定义）提取不同流的载荷包长度序列和JA4指纹等特征。'
        },
        {
          id: 2,
          number: '2',
          title: '知识转换',
          description: '通过精确和模糊匹配载荷长度序列，以及图关联技术，将流量特征数据转换为可理解的知识信息。'
        },
        {
          id: 3,
          number: '3',
          title: 'LLM推理决策',
          description: '将转换后的样本信息输入大语言模型，利用其少样本推理和泛化能力获得最终预测结果。'
        }
      ],
      datasetStats: [
        {
          id: 1,
          number: '2,044',
          label: 'PCAP文件'
        },
        {
          id: 2,
          number: '2019-2024',
          label: '时间跨度'
        },
        {
          id: 3,
          number: '多组织',
          label: 'APT组织'
        },
        {
          id: 4,
          number: '真实',
          label: '攻击流量'
        }
      ]
    }
  },
  methods: {
    copyCitation() {
      const citation = `@inproceedings{aptsniffer2025,
  title={APTSniffer: Detecting APT Attack Traffic Using Retrieval-Augmented Large Language Models},
  author={Your Name and Co-authors},
  booktitle={IEEE International Conference on Acoustics, Speech and Signal Processing (ICASSP)},
  year={2025},
  organization={IEEE}
}`
      navigator.clipboard.writeText(citation).then(() => {
        this.$message.success('引用信息已复制到剪贴板')
      })
    }
  }
}
</script>

<style scoped>
.project-container {
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
  max-width: 900px;
  margin: 0 auto;
}

.conference-badge {
  display: inline-block;
  background: rgba(255, 255, 255, 0.2);
  padding: 8px 20px;
  border-radius: 20px;
  font-size: 0.9rem;
  font-weight: 600;
  margin-bottom: 20px;
  backdrop-filter: blur(10px);
}

.hero-title {
  font-size: 3.5rem;
  font-weight: 800;
  margin-bottom: 15px;
  background: linear-gradient(45deg, #fff, #e0e7ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hero-subtitle {
  font-size: 1.8rem;
  font-weight: 400;
  margin-bottom: 20px;
  opacity: 0.95;
  line-height: 1.4;
}

.hero-description {
  font-size: 1.3rem;
  opacity: 0.9;
  max-width: 700px;
  margin: 0 auto;
  line-height: 1.6;
}

.section-header {
  text-align: center;
  margin: 80px 0 50px;
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

.challenge-card {
  max-width: 800px;
  margin: 0 auto;
  border: none;
  border-radius: 16px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
}

.challenge-content {
  display: flex;
  align-items: center;
  gap: 30px;
  padding: 40px;
}

.challenge-icon {
  font-size: 4rem;
  flex-shrink: 0;
}

.challenge-text {
  flex: 1;
}

.challenge-description {
  font-size: 1.2rem;
  color: #2c3e50;
  line-height: 1.8;
  margin-bottom: 20px;
}

.solution-text {
  font-size: 1.2rem;
  color: #4a90e2;
  font-weight: 500;
  line-height: 1.8;
}

.workflow-section {
  padding: 0 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.workflow-steps {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 30px;
  position: relative;
}

.workflow-step {
  flex: 1;
  min-width: 250px;
  text-align: center;
  position: relative;
  padding: 30px 20px;
  background: #f8f9fa;
  border-radius: 16px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
  transition: all 0.3s ease;
}

.workflow-step:hover {
  transform: translateY(-5px);
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.step-number {
  width: 50px;
  height: 50px;
  background: #4a90e2;
  color: white;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0 auto 20px;
}

.step-title {
  font-size: 1.4rem;
  font-weight: 700;
  color: #2c3e50;
  margin-bottom: 15px;
}

.step-description {
  color: #7f8c8d;
  line-height: 1.7;
  font-size: 1rem;
}

.step-arrow {
  position: absolute;
  top: 45px;
  right: -25px;
  font-size: 2rem;
  color: #4a90e2;
  font-weight: bold;
}

.dataset-section {
  padding: 0 20px;
  max-width: 1200px;
  margin: 0 auto 80px;
}

.dataset-stats {
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 40px;
}

.stat-item {
  text-align: center;
}

.stat-number {
  font-size: 3rem;
  font-weight: 800;
  color: #4a90e2;
  margin-bottom: 10px;
}

.stat-label {
  font-size: 1.2rem;
  color: #2c3e50;
  font-weight: 500;
}

.citation-section {
  padding: 0 20px 80px;
  max-width: 800px;
  margin: 0 auto;
}

.citation-card {
  border: none;
  border-radius: 16px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
}

.citation-content {
  padding: 40px;
}

.citation-content p {
  font-size: 1.1rem;
  color: #2c3e50;
  line-height: 1.8;
  margin-bottom: 30px;
}

.citation-code {
  background: #f8f9fa;
  padding: 20px;
  border-radius: 8px;
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 0.9rem;
  color: #2c3e50;
  line-height: 1.6;
  margin-bottom: 30px;
  overflow-x: auto;
}

.copy-button {
  background-color: #4a90e2 !important;
  border-color: #4a90e2 !important;
  padding: 12px 24px;
  font-size: 1rem;
}

.footer-section {
  background: #2c3e50;
  color: white;
  padding: 40px 20px;
  text-align: center;
}

.footer-content p {
  margin: 0;
  font-size: 1rem;
  opacity: 0.8;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .hero-title {
    font-size: 2.5rem;
  }

  .hero-subtitle {
    font-size: 1.3rem;
  }

  .hero-description {
    font-size: 1.1rem;
  }

  .section-title {
    font-size: 2rem;
  }

  .challenge-content {
    flex-direction: column;
    text-align: center;
  }

  .challenge-icon {
    margin-bottom: 20px;
  }

  .workflow-steps {
    flex-direction: column;
  }

  .step-arrow {
    display: none;
  }

  .dataset-stats {
    gap: 20px;
  }

  .stat-number {
    font-size: 2rem;
  }
}
</style>