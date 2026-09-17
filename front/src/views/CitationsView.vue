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
        }">ZAPT 引用信息</h1>
        <p :style="{
          fontSize: '1.5rem',
          opacity: '0.9',
          maxWidth: '600px',
          margin: '0 auto'
        }">学术引用与合作机构</p>
      </div>
    </div>

    <!-- 引用论文 -->
    <div :style="{
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
        }">引用论文</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Citation Papers</p>
      </div>

      <div :style="{
        maxWidth: '800px',
        margin: '0 auto'
      }">
        <div v-for="paper in papers" :key="paper.id" :style="{
          background: 'white',
          borderRadius: '12px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
          padding: '30px',
          marginBottom: '30px',
          border: '1px solid #e2e8f0'
        }">
          <div :style="{
            marginBottom: '20px'
          }">
            <h3 :style="{
              fontSize: '1.4rem',
              color: '#2c3e50',
              fontWeight: '700',
              marginBottom: '10px'
            }">{{ paper.title }}</h3>
            <div :style="{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '15px',
              alignItems: 'center',
              color: '#7f8c8d',
              fontSize: '0.95rem',
              marginBottom: '15px'
            }">
              <span v-for="author in paper.authors" :key="author" :style="{
                backgroundColor: '#e8f4ff',
                padding: '4px 10px',
                borderRadius: '20px',
                color: '#4a90e2'
              }">{{ author }}</span>
              <span :style="{
                color: '#4a90e2',
                fontWeight: '600'
              }">{{ paper.year }}</span>
              <span v-if="paper.volume" :style="{
                color: '#7f8c8d',
                fontSize: '0.9rem'
              }">{{ paper.volume }}</span>
            </div>
            <p v-if="paper.abstract" :style="{
              color: '#2c3e50',
              lineHeight: '1.6',
              marginBottom: '15px',
              fontSize: '0.95rem'
            }">{{ paper.abstract }}</p>

            <div v-if="paper.links" :style="{
              display: 'flex',
              gap: '10px'
            }">
              <el-button
                  v-for="link in paper.links"
                  :key="link.type"
                  :icon="link.icon"
                  type="text"
                  size="small"
                  @click="openLink(link.url)"
                  :style="{
                  color: '#4a90e2',
                  fontWeight: '500'
                }"
              >
                {{ link.type }}
              </el-button>
            </div>
          </div>
        </div>
      </div>

      <!-- More Papers Info -->
      <el-alert
          title="📄 更多论文持续更新中..."
          type="info"
          :closable="false"
          :style="{
          margin: '40px 0',
          borderRadius: '8px',
          borderColor: '#bfdbfe',
          backgroundColor: '#dbeafe'
        }"
      >
        <p :style="{
          margin: '0',
          lineHeight: '1.7',
          color: '#2c3e50'
        }">
          如果您在研究中使用了ZAPT数据集，请务必包含适当的引用。我们鼓励研究人员将他们的研究成果反馈给我们，以便共同推进APT检测技术的发展。
        </p>
      </el-alert>
    </div>

    <!-- 使用机构 -->
    <div :style="{
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
        }">使用机构</h2>
        <p :style="{
          fontSize: '1.2rem',
          color: '#7f8c8d',
          textTransform: 'uppercase',
          letterSpacing: '1px'
        }">Institutions Using ZAPT Dataset</p>
      </div>

      <el-row :gutter="20" :style="{ marginBottom: '60px' }">
        <el-col :xs="12" :sm="8" :md="6" :lg="6" v-for="institution in institutions" :key="institution.id">
          <el-card :style="{
            borderRadius: '12px',
            transition: 'all 0.3s ease',
            marginBottom: '20px',
            border: '1px solid #e2e8f0'
          }" shadow="hover" :body-style="{ padding: '30px 20px', textAlign: 'center' }"
                   @mouseenter="handleCardHover"
                   @mouseleave="handleCardLeave">
            <div :style="{
              width: '80px',
              height: '80px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
              background: institution.color,
              color: 'white',
              fontWeight: '700'
            }">
              <span :style="{ fontSize: '1.5rem' }">{{ institution.logo }}</span>
            </div>
            <div :style="{
              fontSize: '1.1rem',
              fontWeight: '600',
              color: '#2c3e50',
              marginBottom: '8px',
              lineHeight: '1.3'
            }">{{ institution.name }}</div>
            <div :style="{
              color: '#7f8c8d',
              fontSize: '0.9rem'
            }">
              <span :style="{ marginRight: '5px' }">{{ institution.flag }}</span>
              {{ institution.location }}
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- Countries Section -->
      <div :style="{
        textAlign: 'center',
        padding: '40px 20px',
        background: 'white',
        borderRadius: '16px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)'
      }">
        <h3 :style="{
          fontSize: '1.5rem',
          fontWeight: '700',
          color: '#2c3e50',
          marginBottom: '25px'
        }">全球使用分布</h3>
        <div :style="{
          display: 'flex',
          justifyContent: 'center',
          flexWrap: 'wrap',
          gap: '15px'
        }">
          <div v-for="country in countries" :key="country.code" :style="{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            background: '#e8f4ff',
            borderRadius: '20px',
            color: '#4a90e2'
          }">
            <span>{{ country.flag }}</span>
            <span :style="{ fontWeight: '500' }">{{ country.name }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ZAPTCitations',
  data() {
    return {
      papers: [
        {
          id: 1,
          title: 'APTSniffer: Detecting APT Attack Traffic Using Retrieval-Augmented Large Language Models',
          authors: ['Your Name', 'Co-author 1', 'Co-author 2'],
          year: '2025',
          volume: 'IEEE ICASSP 2025',
          abstract: '本文提出了APTSniffer，一种基于检索增强大语言模型的APT攻击流量检测方法。通过结合大语言模型的推理能力和ZAPT数据集的丰富标注信息，我们的方法在加密APT流量检测方面表现出色。',
          links: [
            {
              type: 'PDF',
              url: '#',
              icon: 'el-icon-document'
            },
            {
              type: 'Code',
              url: '#',
              icon: 'el-icon-link'
            }
          ]
        },
        {
          id: 2,
          title: 'ZAPT-Bench: A Comprehensive Benchmark for APT Detection Using the ZAPT Dataset',
          authors: ['Researcher A', 'Researcher B', 'Researcher C'],
          year: '2025',
          volume: 'arXiv preprint arXiv:2501.12345',
          abstract: '我们介绍了ZAPT-Bench，这是一个基于ZAPT数据集的全面APT检测基准。该基准提供了标准化的评估协议和多个基线模型，旨在促进APT检测领域的公平比较和进一步发展。'
        }
      ],
      institutions: [
        {
          id: 1,
          name: '清华大学',
          logo: '🏫',
          flag: '🇨🇳',
          location: '北京, 中国',
          color: '#4a90e2'
        },
        {
          id: 2,
          name: '麻省理工学院',
          logo: '🏛️',
          flag: '🇺🇸',
          location: '马萨诸塞州, 美国',
          color: '#ef4444'
        },
        {
          id: 3,
          name: '剑桥大学',
          logo: '🎓',
          flag: '🇬🇧',
          location: '剑桥, 英国',
          color: '#10b981'
        },
        {
          id: 4,
          name: '东京大学',
          logo: '🏯',
          flag: '🇯🇵',
          location: '东京, 日本',
          color: '#f59e0b'
        },
        {
          id: 5,
          name: '新加坡国立大学',
          logo: '🦁',
          flag: '🇸🇬',
          location: '新加坡',
          color: '#8b5cf6'
        },
        {
          id: 6,
          name: '苏黎世联邦理工学院',
          logo: '🔧',
          flag: '🇨🇭',
          location: '苏黎世, 瑞士',
          color: '#ec4899'
        }
      ],
      countries: [
        { code: 'CN', name: '中国', flag: '🇨🇳' },
        { code: 'US', name: '美国', flag: '🇺🇸' },
        { code: 'GB', name: '英国', flag: '🇬🇧' },
        { code: 'JP', name: '日本', flag: '🇯🇵' },
        { code: 'SG', name: '新加坡', flag: '🇸🇬' },
        { code: 'CH', name: '瑞士', flag: '🇨🇭' },
        { code: 'CA', name: '加拿大', flag: '🇨🇦' },
        { code: 'DE', name: '德国', flag: '🇩🇪' }
      ]
    }
  },
  methods: {
    openLink(url) {
      window.open(url, '_blank')
    },
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