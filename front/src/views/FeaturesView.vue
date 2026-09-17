<template>
  <div :style="{
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #4a90e2 0%, #764ba2 100%)'
  }">
    <!-- Hero Section -->
    <div :style="{
      background: 'linear-gradient(135deg, rgba(74, 144, 226, 0.9), rgba(118, 75, 162, 0.9))',
      color: 'white',
      padding: '80px 20px',
      textAlign: 'center'
    }">
      <div :style="{
        maxWidth: '800px',
        margin: '0 auto'
      }">
        <h1 :style="{
          fontSize: '3rem',
          fontWeight: '700',
          marginBottom: '20px',
          background: 'linear-gradient(45deg, #fff, #e0e7ff)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text'
        }">ZAPT 数据集特色</h1>
        <p :style="{
          fontSize: '1.5rem',
          opacity: '0.9',
          maxWidth: '600px',
          margin: '0 auto'
        }">已知数据最丰富、标注最精细、时间跨度最大的APT流量数据集</p>
      </div>
    </div>

    <!-- 数据集规模 -->
    <section :style="{
      padding: '80px 20px',
      background: 'white'
    }">
      <div :style="{
        textAlign: 'center',
        marginBottom: '60px'
      }">
        <h2 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '15px'
        }">数据集规模</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Dataset Scale</p>
      </div>

      <div :style="{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '30px',
        marginBottom: '40px'
      }">
        <div v-for="stat in attackStats" :key="stat.id" :style="{
          textAlign: 'center',
          padding: '30px 20px',
          background: 'white',
          borderRadius: '12px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)'
        }">
          <div :style="{
            fontSize: '3rem',
            fontWeight: '800',
            color: '#4a90e2',
            marginBottom: '10px'
          }">{{ stat.value }}</div>
          <div :style="{
            color: '#2c3e50',
            fontWeight: '600',
            fontSize: '1.1rem'
          }">{{ stat.label }}</div>
        </div>
      </div>

      <div :style="{
        background: 'linear-gradient(135deg, #e8f4ff 0%, #dbeafe 100%)',
        padding: '30px',
        borderRadius: '12px',
        borderLeft: '4px solid #4a90e2',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '20px',
        maxWidth: '800px',
        margin: '0 auto'
      }">
        <div :style="{
          fontSize: '2rem',
          flexShrink: '0',
          color: '#4a90e2'
        }">💡</div>
        <div>
          <h4 :style="{
            fontSize: '1.3rem',
            color: '#2c3e50',
            marginBottom: '10px',
            fontWeight: '600'
          }">场景特点</h4>
          <p :style="{
            color: '#2c3e50',
            lineHeight: '1.8',
            fontSize: '0.95rem',
            whiteSpace: 'pre-line'
          }">覆盖ATT&CK框架战术和技术
包含多个APT组织的攻击手法
万级数据规模，支持深度学习模型训练</p>
        </div>
      </div>
    </section>

    <!-- 构建方法 -->
    <section :style="{
      padding: '80px 20px',
      background: '#f8f9fa'
    }">
      <div :style="{
        textAlign: 'center',
        marginBottom: '60px'
      }">
        <h2 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '15px'
        }">构建方法</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Construction Methods</p>
      </div>

      <div :style="{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '30px'
      }">
        <div v-for="method in constructionMethods" :key="method.id" :style="{
          background: 'white',
          padding: '40px 30px',
          borderRadius: '16px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
          textAlign: 'center',
          transition: 'all 0.3s ease'
        }" @mouseenter="handleCardHover" @mouseleave="handleCardLeave">
          <div :style="{
            fontSize: '4rem',
            marginBottom: '20px'
          }">{{ method.icon }}</div>
          <h3 :style="{
            fontSize: '1.4rem',
            color: '#2c3e50',
            marginBottom: '15px',
            fontWeight: '600'
          }">{{ method.title }}</h3>
          <p :style="{
            color: '#7f8c8d',
            lineHeight: '1.7',
            fontSize: '0.95rem'
          }">{{ method.description }}</p>
        </div>
      </div>
    </section>

    <!-- 数据来源分布 -->
    <section :style="{
      padding: '80px 20px',
      background: 'white'
    }">
      <div :style="{
        textAlign: 'center',
        marginBottom: '60px'
      }">
        <h2 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '15px'
        }">数据来源分布</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Data Sources Distribution</p>
      </div>

      <div :style="{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
        gap: '25px'
      }">
        <div v-for="source in dataSources" :key="source.id" :style="{
          background: 'white',
          padding: '30px 25px',
          borderRadius: '12px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
          display: 'flex',
          alignItems: 'center',
          gap: '20px',
          transition: 'all 0.3s ease'
        }" @mouseenter="handleCardHover" @mouseleave="handleCardLeave">
          <div :style="{
            fontSize: '2rem'
          }">{{ source.icon }}</div>
          <div>
            <div :style="{
              fontSize: '1.8rem',
              fontWeight: '700',
              color: '#4a90e2',
              marginBottom: '5px'
            }">{{ source.count }}</div>
            <div :style="{
              color: '#2c3e50',
              fontWeight: '500'
            }">{{ source.name }}</div>
            <div :style="{
              color: '#7f8c8d',
              fontSize: '0.85rem',
              marginTop: '3px'
            }">{{ source.description }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- 关键特性 -->
    <section :style="{
      padding: '80px 20px',
      background: '#f8f9fa'
    }">
      <div :style="{
        textAlign: 'center',
        marginBottom: '60px'
      }">
        <h2 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '15px'
        }">关键特性</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Key Features</p>
      </div>

      <div :style="{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '30px'
      }">
        <div v-for="feature in keyFeatures" :key="feature.id" :style="{
          background: 'white',
          padding: '40px 30px',
          borderRadius: '16px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
          textAlign: 'center',
          transition: 'all 0.3s ease'
        }" @mouseenter="handleCardHover" @mouseleave="handleCardLeave">
          <div :style="{
            fontSize: '4rem',
            marginBottom: '20px'
          }">{{ feature.icon }}</div>
          <h3 :style="{
            fontSize: '1.4rem',
            color: '#2c3e50',
            marginBottom: '15px',
            fontWeight: '600'
          }">{{ feature.title }}</h3>
          <p :style="{
            color: '#7f8c8d',
            lineHeight: '1.7',
            fontSize: '0.95rem'
          }">{{ feature.description }}</p>
        </div>
      </div>
    </section>

    <!-- 科研成果 -->
    <section :style="{
      padding: '80px 20px',
      background: 'white'
    }">
      <div :style="{
        textAlign: 'center',
        marginBottom: '60px'
      }">
        <h2 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '15px'
        }">科研成果</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Research Achievements</p>
      </div>

      <div :style="{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: '30px'
      }">
        <div v-for="achievement in researchAchievements" :key="achievement.id" :style="{
          background: 'white',
          padding: '40px',
          borderRadius: '16px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '25px',
          transition: 'all 0.3s ease'
        }" @mouseenter="handleCardHover" @mouseleave="handleCardLeave">
          <div :style="{
            fontSize: '4rem',
            flexShrink: '0',
            color: '#4a90e2'
          }">{{ achievement.icon }}</div>
          <div :style="{
            flex: '1'
          }">
            <h3 :style="{
              fontSize: '1.8rem',
              color: '#2c3e50',
              marginBottom: '15px',
              fontWeight: '700'
            }">{{ achievement.title }}</h3>
            <p :style="{
              color: '#2c3e50',
              lineHeight: '1.8',
              fontSize: '1rem',
              whiteSpace: 'pre-line'
            }">{{ achievement.description }}</p>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script>
export default {
  name: 'ZAPTFeatures',
  data() {
    return {
      datasetStats: [
        { id: 1, value: '29,668', label: 'PCAP 文件数量', unit: '个' },
        { id: 2, value: '11.4', label: '数据总量', unit: 'GB' },
        { id: 3, value: '23', label: '覆盖网络侧TTP', unit: '种 / 共53种' },
        { id: 4, value: '43.3', label: 'TTP 覆盖率', unit: '%' }
      ],
      constructionMethods: [
        {
          id: 1,
          icon: '🌐',
          title: '现网捕获',
          description: '从真实网络环境中捕获APT攻击流量，基于Any.run沙箱平台和VirusTotal，确保数据的真实性和有效性。'
        },
        {
          id: 2,
          icon: '⚔️',
          title: '模拟攻击',
          description: '使用Metasploit、Nmap等专业工具模拟真实APT攻击场景，构建多步攻击链，覆盖完整的攻击生命周期。'
        },
        {
          id: 3,
          icon: '🧪',
          title: '样本养殖',
          description: '通过恶意软件流量数据集获取APT样本流量，经过Suricata IDS验证和Tshark提取，确保标签准确性。'
        },
        {
          id: 4,
          icon: '🤖',
          title: 'AI 生成',
          description: '利用人工智能技术生成大规模流量数据，扩充数据集规模，达到万级数据量，支持深度学习模型训练。'
        }
      ],
      dataSources: [
        { id: 1, icon: '🔬', name: 'Any.run', count: 3240, description: '真实APT攻击样本' },
        { id: 2, icon: '🦠', name: 'VirusTotal', count: 23398, description: '恶意软件流量样本' },
        { id: 3, icon: '📦', name: 'Malware Dataset', count: 3006, description: 'APT/Qbot/CS流量' },
        { id: 4, icon: '⚡', name: '模拟攻击', count: 24, description: 'Metasploit/Nmap' }
      ],
      keyFeatures: [
        {
          id: 1,
          icon: '🎯',
          title: '精细化',
          description: '子TTP级别的精细标注，支持TA/TTP/APT/MD5等多维度标签体系'
        },
        {
          id: 2,
          icon: '🏷️',
          title: '多标签',
          description: '丰富的标签维度：战术（TA）、技术（TTP）、APT组织、样本哈希值'
        },
        {
          id: 3,
          icon: '📖',
          title: '可解释',
          description: '恶意行为描述清晰，便于理解和分析，支持安全研究和教学应用'
        },
        {
          id: 4,
          icon: '🌐',
          title: '高覆盖',
          description: '覆盖ATT&CK框架战术和技术，涵盖多个APT组织的攻击手法'
        },
        {
          id: 5,
          icon: '💎',
          title: '高质量',
          description: '纯净、逼真的流量数据，经过严格质量验证和人工审核'
        },
        {
          id: 6,
          icon: '📈',
          title: '规模化',
          description: '万级数据规模，支持AI深度学习模型训练和大规模实验'
        }
      ],
      attackStats: [
        { id: 1, value: '5', label: 'APT组织' },
        { id: 2, value: '10', label: '攻击场景' },
        { id: 3, value: '24', label: '攻击阶段' },
        { id: 4, value: '53', label: 'TTP技术' }
      ],
      researchAchievements: [
        {
          id: 1,
          icon: '🏆',
          title: 'ICASSP 2025',
          description: 'APTSniffer: Detecting APT Attack Traffic Using Retrieval-Augmented Large Language Models'
        },
        {
          id: 2,
          icon: '🏅',
          title: '数据集基准',
          description: 'ZAPT-Benchmark: 基于ZAPT数据集的APT检测模型评估基准，支持公平、一致的性能对比'
        }
      ]
    }
  },
  methods: {
    handleCardHover(event) {
      event.currentTarget.style.transform = 'translateY(-5px)'
      event.currentTarget.style.boxShadow = '0 20px 25px rgba(0, 0, 0, 0.1)'
    },
    handleCardLeave(event) {
      event.currentTarget.style.transform = 'translateY(0)'
      event.currentTarget.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.05)'
    }
  }
}
</script>