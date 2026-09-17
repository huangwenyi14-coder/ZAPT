<template>
  <div style="min-height: 100vh; background: linear-gradient(135deg, #4a90e2 0%, #764ba2 100%);">
    <!-- Hero Section -->
    <div style="background: linear-gradient(135deg, rgba(74, 144, 226, 0.9), rgba(118, 75, 162, 0.9)); color: white; padding: 80px 20px; text-align: center;">
      <div style="max-width: 800px; margin: 0 auto;">
        <h1 style="font-size: 3rem; font-weight: 700; margin-bottom: 20px; background: linear-gradient(45deg, #fff, #e0e7ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
          ZAPT Dataset
        </h1>
        <p style="font-size: 1.5rem; opacity: 0.9; max-width: 600px; margin: 0 auto 30px;">
          大规模APT攻击流量数据集
        </p>
        <p style="font-size: 1.1rem; opacity: 0.8; line-height: 1.6;">
          包含2044个真实APT攻击PCAP文件的大规模数据集，涵盖2019-2024年多个APT组织的攻击流量，为网络安全研究提供高质量数据支持。
        </p>
      </div>
    </div>

    <!-- 数据集统计卡片 -->
    <div style="padding: 60px 20px; background: white; max-width: 1200px; margin: -40px auto 0; border-radius: 20px; position: relative; z-index: 10; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);">
      <el-row :gutter="30">
        <el-col :xs="12" :sm="6" v-for="stat in stats" :key="stat.id">
          <el-card
              style="border-radius: 12px; background: rgba(255, 255, 255, 0.95); border: none; margin-bottom: 30px;"
              shadow="hover"
              @mouseenter="handleCardHover"
              @mouseleave="handleCardLeave"
          >
            <div style="padding: 30px 25px; text-align: center;">
              <div style="font-size: 3rem; margin-bottom: 20px; color: #4a90e2;">
                {{ stat.icon }}
              </div>
              <div style="font-size: 2rem; font-weight: 700; color: #2c3e50; margin-bottom: 10px;">
                {{ stat.value }}
              </div>
              <div style="color: #7f8c8d; line-height: 1.6; font-size: 0.95rem;">
                {{ stat.label }}
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- 数据集统计详情 -->
      <el-card style="border-radius: 16px; background: rgba(255, 255, 255, 0.95); border: none; margin-bottom: 60px;" shadow="hover">
        <div style="padding: 40px;">
          <div style="text-align: center; margin-bottom: 40px;">
            <h3 style="font-size: 2rem; font-weight: 700; color: #2c3e50; margin-bottom: 10px;">数据集统计</h3>
            <p style="font-size: 1.1rem; color: #7f8c8d;">Dataset Statistics</p>
          </div>

          <div style="color: #2c3e50; line-height: 1.7; margin-bottom: 15px;">
            <p>ZAPT数据集包含2044个真实的APT攻击PCAP文件，涵盖2019-2024年间多个知名APT组织的攻击流量，为网络安全研究提供了宝贵的数据资源。</p>
          </div>
          <div style="color: #2c3e50; line-height: 1.7; margin-bottom: 30px;">
            <p>所有流量数据均经过严格的筛选和标注，确保数据质量和可用性。数据集涵盖了多种攻击技术和战术，适用于各种网络安全研究和分析任务。</p>
          </div>

          <div style="background: #f8f9fa; padding: 30px; border-radius: 12px; margin-bottom: 30px;">
            <div style="color: #10b981; font-size: 0.9rem; margin-bottom: 15px;">PCAP文件命名规则</div>
            <div style="color: #2c3e50; font-size: 0.85rem; line-height: 1.5;">
              APT_APT10-20230130-684888079aaf7ed25e725b55a3695062-5_192.168.100.23_58521_37.48.65.148_80_sid-2826183_ttp-T1041_ta-TA0011.pcap
            </div>
          </div>

          <el-row :gutter="30">
            <el-col :xs="24" :sm="12" v-for="example in examples" :key="example.id">
              <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
                <div style="display: flex; align-items: center; margin-bottom: 15px;">
                  <div style="width: 40px; height: 40px; border-radius: 8px; background: #4a90e2; display: flex; align-items: center; justify-content: center; color: white; font-weight: 600; margin-right: 15px;">
                    {{ example.icon }}
                  </div>
                  <div style="font-weight: 600; color: #2c3e50;">{{ example.title }}</div>
                </div>
                <div style="color: #7f8c8d; font-size: 0.9rem;">{{ example.content }}</div>
              </div>
            </el-col>
          </el-row>
        </div>
      </el-card>

      <!-- 应用场景 -->
      <div style="text-align: center; margin-bottom: 60px;">
        <h2 style="font-size: 2.5rem; font-weight: 700; color: white; margin-bottom: 15px;">应用场景</h2>
        <p style="font-size: 1.2rem; color: rgba(255, 255, 255, 0.9);">Application Scenarios</p>
      </div>

      <el-row :gutter="30">
        <el-col :xs="24" :sm="12" :md="8" v-for="feature in features" :key="feature.id">
          <el-card
              style="border-radius: 12px; background: rgba(255, 255, 255, 0.95); border: none; margin-bottom: 30px;"
              shadow="hover"
              @mouseenter="handleCardHover"
              @mouseleave="handleCardLeave"
          >
            <div style="padding: 30px 25px; text-align: center;">
              <div style="font-size: 3rem; margin-bottom: 20px;">
                {{ feature.icon }}
              </div>
              <div style="font-size: 1.3rem; font-weight: 600; color: #2c3e50; margin-bottom: 15px;">
                {{ feature.title }}
              </div>
              <div style="color: #7f8c8d; line-height: 1.6; font-size: 0.95rem;">
                {{ feature.description }}
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 引用信息 -->
    <div style="padding: 80px 20px; background: rgba(255, 255, 255, 0.95);">
      <div style="max-width: 800px; margin: 0 auto; text-align: center;">
        <h2 style="font-size: 2.5rem; font-weight: 700; color: #2c3e50; margin-bottom: 20px;">引用信息</h2>
        <p style="font-size: 1.2rem; color: #7f8c8d; margin-bottom: 40px;">
          Citation Information
        </p>

        <el-card style="border-radius: 12px; border: 1px solid #e2e8f0; margin-bottom: 30px;" shadow="never">
          <div style="padding: 30px; text-align: left;">
            <p style="color: #2c3e50; line-height: 1.8; margin-bottom: 20px;">
              如果您在研究中使用了本数据集，请务必包含适当的引用：
            </p>
            <div style="background: #f8fafc; padding: 20px; border-radius: 8px; font-family: 'Monaco', 'Consolas', monospace; font-size: 0.85rem; color: #4a5568; line-height: 1.6; overflow-x: auto;">
              @inproceedings{zapt2025,<br>
              &nbsp;&nbsp;title={ZAPT: A Large-scale APT Attack Traffic Dataset for Cybersecurity Research},<br>
              &nbsp;&nbsp;author={Your Name and Co-authors},<br>
              &nbsp;&nbsp;booktitle={IEEE International Conference on Acoustics, Speech and Signal Processing (ICASSP)},<br>
              &nbsp;&nbsp;year={2025},<br>
              &nbsp;&nbsp;organization={IEEE}<br>
              }
            </div>
            <el-button type="primary" @click="handleDownload" style="margin-top: 20px; background-color: #4a90e2; border-color: #4a90e2;">
              <i class="el-icon-download"></i>
              下载数据集
            </el-button>
          </div>
        </el-card>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'DatasetDescription',
  data() {
    return {
      stats: [
        { id: 1, icon: '📁', value: '2,044', label: 'PCAP 文件' },
        { id: 2, icon: '📅', value: '2019-2024', label: '时间跨度' },
        { id: 3, icon: '🏢', value: '5+', label: 'APT 组织' },
        { id: 4, icon: '📊', value: '真实', label: '攻击流量' }
      ],
      examples: [
        {
          id: 1,
          icon: '🔢',
          title: '文件名组成',
          content: '文件名包含了丰富的元数据信息，如APT组织、时间戳、源IP、目标IP、Suricata规则ID、TTP和TA等。'
        },
        {
          id: 2,
          icon: '🔍',
          title: '精细标注',
          content: '每个PCAP文件都经过精细标注，包含ATT&CK框架中的战术(TA)和技术(TTP)信息。'
        }
      ],
      features: [
        {
          id: 1,
          icon: '🛡️',
          title: '威胁检测',
          description: '用于开发和测试APT攻击检测系统，提高威胁识别准确率。'
        },
        {
          id: 2,
          icon: '🧩',
          title: '行为分析',
          description: '分析APT组织的攻击模式、TTP（战术、技术和程序）、攻击链演变等。'
        },
        {
          id: 3,
          icon: '🎓',
          title: '教学与培训',
          description: '用于网络安全课程教学、CTF竞赛训练、安全分析师培训等教育场景。'
        },
        {
          id: 4,
          icon: '🛡️',
          title: '防御系统开发',
          description: '开发和测试入侵检测系统、防火墙规则、安全事件响应流程等防御技术。'
        },
        {
          id: 5,
          icon: '🔬',
          title: '学术研究',
          description: '支持网络安全领域的学术研究，发表高水平论文，推动技术创新。'
        }
      ]
    }
  },
  methods: {
    handleCardHover(event) {
      event.currentTarget.style.transform = 'translateY(-5px)'
      event.currentTarget.style.boxShadow = '0 10px 25px rgba(0, 0, 0, 0.1)'
    },
    handleCardLeave(event) {
      event.currentTarget.style.transform = 'translateY(0)'
      event.currentTarget.style.boxShadow = '0 2px 12px 0 rgba(0, 0, 0, 0.1)'
    },
    handleDownload() {
      this.$message.success('数据集下载链接已发送到您的邮箱')
    }
  }
}
</script>