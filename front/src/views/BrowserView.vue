<template>
  <div :style="{ minHeight: '100vh', background: '#f8f9fa' }">
    <!-- Hero Section -->
    <div :style="{
      background: 'linear-gradient(135deg, #4a90e2 0%, #764ba2 100%)',
      color: 'white',
      padding: '60px 20px',
      textAlign: 'center'
    }">
      <div :style="{ maxWidth: '800px', margin: '0 auto' }">
        <h1 :style="{
          fontSize: '2.5rem',
          fontWeight: '700',
          marginBottom: '20px'
        }">ZAPT 数据集浏览器</h1>
        <p :style="{
          fontSize: '1.2rem',
          opacity: '0.9',
          maxWidth: '600px',
          margin: '0 auto'
        }">探索和分析大规模APT攻击流量数据集</p>
        <el-button
            @click="showDownloadModal"
            type="primary"
            :style="{
              marginTop: '30px',
              padding: '12px 30px',
              fontSize: '16px',
              fontWeight: '600',
              background: '#4a90e2',
              borderColor: '#4a90e2'
            }">
          <i class="el-icon-download"></i>
          获取数据集
        </el-button>
      </div>
    </div>

    <!-- Main Content -->
    <div :style="{
      maxWidth: '1400px',
      margin: '0 auto',
      padding: '30px 20px'
    }">
      <!-- Search and Filter Card -->
      <el-card shadow="hover" :style="{ marginBottom: '20px', borderRadius: '12px' }">
        <div slot="header" :style="{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }">
          <span :style="{
            fontSize: '1.2rem',
            fontWeight: '600',
            color: '#2c3e50'
          }">
            <i class="el-icon-search"></i>
            数据搜索与筛选
          </span>
          <el-tag type="primary">{{ filteredData.length }} 个结果</el-tag>
        </div>

        <div :style="{ marginBottom: '20px' }">
          <el-input
              v-model="searchTerm"
              placeholder="搜索样本哈希值、源IP、目标IP、APT组织..."
              size="large"
              clearable
              @keyup.enter.native="performSearch"
              @clear="performSearch"
          >
            <el-button
                slot="append"
                icon="el-icon-search"
                @click="performSearch"
                style="background-color: #4a90e2; border-color: #4a90e2; color: white;"
            ></el-button>
          </el-input>
        </div>

        <div v-show="showFilters" :style="{ marginBottom: '20px' }">
          <el-row :gutter="20">
            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">APT 组织</div>
                <el-select
                    v-model="filters.apt"
                    placeholder="全部组织"
                    clearable
                    @change="applyFilters"
                    style="width: 100%"
                >
                  <el-option
                      v-for="apt in aptOptions"
                      :key="apt"
                      :label="apt"
                      :value="apt"
                  />
                </el-select>
              </div>
            </el-col>

            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">开始日期</div>
                <el-date-picker
                    v-model="filters.dateStart"
                    type="date"
                    placeholder="选择开始日期"
                    format="yyyy-MM-dd"
                    value-format="yyyy-MM-dd"
                    @change="applyFilters"
                    style="width: 100%"
                />
              </div>
            </el-col>

            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">结束日期</div>
                <el-date-picker
                    v-model="filters.dateEnd"
                    type="date"
                    placeholder="选择结束日期"
                    format="yyyy-MM-dd"
                    value-format="yyyy-MM-dd"
                    @change="applyFilters"
                    style="width: 100%"
                />
              </div>
            </el-col>

            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">ATT&CK 战术</div>
                <el-select
                    v-model="filters.tactic"
                    placeholder="全部战术"
                    clearable
                    @change="applyFilters"
                    style="width: 100%"
                >
                  <el-option
                      v-for="tactic in tacticOptions"
                      :key="tactic"
                      :label="tactic"
                      :value="tactic"
                  />
                </el-select>
              </div>
            </el-col>
            <!-- 在现有的筛选条件后面添加这两个 -->

            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">ATT&CK 技术</div>
                <el-select
                    v-model="filters.technique"
                    placeholder="全部技术"
                    clearable
                    @change="applyFilters"
                    style="width: 100%"
                >
                  <el-option
                      v-for="technique in techniqueOptions"
                      :key="technique"
                      :label="technique"
                      :value="technique"
                  />
                </el-select>
              </div>
            </el-col>
            <el-col :xs="24" :sm="12" :md="8" :lg="4">
              <div :style="{ marginBottom: '15px' }">
                <div :style="{
                  fontSize: '0.9rem',
                  fontWeight: '600',
                  marginBottom: '8px',
                  color: '#2c3e50'
                }">Suricata ID</div>
                <el-input
                    v-model="filters.suricata"
                    placeholder="输入规则ID"
                    clearable
                    @change="applyFilters"
                />
              </div>
            </el-col>
          </el-row>
        </div>

        <div :style="{
          display: 'flex',
          gap: '10px',
          justifyContent: 'flex-end'
        }">
          <el-button
              :type="showFilters ? 'primary' : 'default'"
              @click="toggleFilters"
              :style="showFilters ? 'background-color: #4a90e2; border-color: #4a90e2;' : ''"
          >
            <i class="el-icon-filter"></i>
            {{ showFilters ? '隐藏筛选' : '显示筛选' }}
          </el-button>
          <el-button @click="resetFilters" style="background-color: #6b7280; border-color: #6b7280; color: white;">
            <i class="el-icon-refresh"></i>
            重置条件
          </el-button>
        </div>
      </el-card>

      <!-- Stats Cards -->
      <el-row :gutter="20" :style="{ marginBottom: '20px' }">
        <el-col :xs="12" :sm="6">
          <el-card shadow="hover" :style="{ textAlign: 'center' }">
            <div :style="{ color: '#4a90e2', fontSize: '2rem', fontWeight: 'bold' }">
              {{ pcapData.length }}
            </div>
            <div :style="{ color: '#666', marginTop: '8px' }">
              <i class="el-icon-document"></i> 总样本数
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6">
          <el-card shadow="hover" :style="{ textAlign: 'center' }">
            <div :style="{ color: '#ef4444', fontSize: '2rem', fontWeight: 'bold' }">
              {{ filteredData.length }}
            </div>
            <div :style="{ color: '#666', marginTop: '8px' }">
              <i class="el-icon-data-analysis"></i> 筛选结果
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6">
          <el-card shadow="hover" :style="{ textAlign: 'center' }">
            <div :style="{ color: '#10b981', fontSize: '2rem', fontWeight: 'bold' }">
              {{ aptCount }}
            </div>
            <div :style="{ color: '#666', marginTop: '8px' }">
              <i class="el-icon-office-building"></i> APT 组织
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6">
          <el-card shadow="hover" :style="{ textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }">
            <div :style="{ color: '#f59e0b', fontSize: '0.9rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: '1', lineHeight: '1.2', padding: '0 8px' }">
              {{ dateRange }}
            </div>
            <div :style="{ color: '#666', marginTop: '8px' }">
              <i class="el-icon-date"></i> 日期范围
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- Data Table -->
      <el-card shadow="hover" :style="{ borderRadius: '12px' }">
        <div slot="header" :style="{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }">
          <span :style="{
            fontSize: '1.2rem',
            fontWeight: '600',
            color: '#2c3e50'
          }">
            <i class="el-icon-tickets"></i>
            APT 攻击流量样本
          </span>
          <el-button type="primary" plain @click="exportData" style="background-color: #4a90e2; border-color: #4a90e2; color: #4a90e2;">
            <i class="el-icon-download"></i>
            导出数据
          </el-button>
        </div>

        <el-table
            :data="paginatedData"
            v-loading="loading"
            :style="{ width: '100%' }"
            :header-cell-style="{
              background: 'linear-gradient(135deg, #4a90e2 0%, #764ba2 100%)',
              color: 'white',
              fontWeight: '600'
            }"
            stripe
        >
          <el-table-column prop="apt" label="APT 组织" width="120">
            <template slot-scope="{ row }">
              <el-tag
                  effect="dark"
                  :color="getAptColor(row.apt)"
                  :style="{ border: 'none', fontWeight: '600' }"
              >
                {{ row.apt }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="date" label="日期" width="110" sortable>
            <template slot-scope="{ row }">
              <el-tag type="info" effect="plain">
                {{ row.date }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="hash" label="样本哈希" min-width="180">
            <template slot-scope="{ row }">
              <el-tooltip :content="row.hash" placement="top">
                <span :style="{
                  fontFamily: 'Monaco, Consolas, monospace',
                  fontSize: '0.85rem',
                  color: '#4a90e2'
                }">
                  {{ row.hash.substring(0, 16) }}...
                </span>
              </el-tooltip>
            </template>
          </el-table-column>

          <el-table-column label="网络连接" min-width="200">
            <template slot-scope="{ row }">
              <div :style="{ fontSize: '0.9rem' }">
                <div>
                  <i class="el-icon-right"></i>
                  <span :style="{ fontFamily: 'monospace' }">{{ row.srcIP }}:{{ row.srcPort }}</span>
                </div>
                <div>
                  <i class="el-icon-bottom"></i>
                  <span :style="{ fontFamily: 'monospace' }">{{ row.dstIP }}:{{ row.dstPort }}</span>
                </div>
              </div>
            </template>
          </el-table-column>

          <el-table-column prop="suricata" label="Suricata ID" width="130">
            <template slot-scope="{ row }">
              <el-tag type="warning" effect="light">
                {{ row.suricata }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="tactic" label="ATT&CK 战术" width="140">
            <template slot-scope="{ row }">
              <el-tooltip :content="row.tacticName" placement="top">
                <el-tag type="danger" effect="light">
                  {{ row.tactic }}
                </el-tag>
              </el-tooltip>
            </template>
          </el-table-column>

          <el-table-column prop="technique" label="ATT&CK 技术" width="140">
            <template slot-scope="{ row }">
              <el-tooltip :content="row.techniqueName" placement="top">
                <el-tag type="success" effect="light">
                  {{ row.technique }}
                </el-tag>
              </el-tooltip>
            </template>
          </el-table-column>

          <el-table-column label="操作" width="150" fixed="right">
            <template slot-scope="{ row }">
              <div style="display: flex; align-items: center; gap: 4px; justify-content: center;">
                <el-button
                    type="primary"
                    icon="el-icon-view"
                    size="mini"
                    @click="showDetail(row)"
                    circle
                    style="background-color: #4a90e2; border-color: #4a90e2;"
                ></el-button>
                <el-button
                    type="success"
                    icon="el-icon-download"
                    size="mini"
                    @click="downloadSample(row)"
                    circle
                    style="background-color: #10b981; border-color: #10b981;"
                ></el-button>
              </div>
            </template>
          </el-table-column>
        </el-table>

        <!-- Pagination -->
        <div :style="{ display: 'flex', justifyContent: 'center', marginTop: '20px' }">
          <el-pagination
              @size-change="handleSizeChange"
              @current-change="handleCurrentChange"
              :current-page="currentPageNum"
              :page-sizes="[10, 20, 50, 100]"
              :page-size="itemsPerPage"
              layout="total, sizes, prev, pager, next, jumper"
              :total="filteredData.length"
              background
              style="--el-pagination-background-color: #4a90e2; --el-pagination-button-disabled-bg-color: #e5e7eb;"
          >
          </el-pagination>
        </div>
      </el-card>
    </div>

    <!-- Detail Modal -->
    <el-dialog :visible.sync="showDetailModal" title="样本详情" width="600px">
      <div v-if="selectedItem">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="APT 组织">
            <el-tag
                effect="dark"
                :color="getAptColor(selectedItem.apt)"
                :style="{ border: 'none', fontWeight: '600' }"
            >
              {{ selectedItem.apt }}
            </el-tag>
          </el-descriptions-item>

          <el-descriptions-item label="日期">
            <el-tag type="info">{{ selectedItem.date }}</el-tag>
          </el-descriptions-item>

          <el-descriptions-item label="样本哈希">
            <span :style="{ fontFamily: 'Monaco, Consolas, monospace', color: '#4a90e2' }">
              {{ selectedItem.hash }}
            </span>
          </el-descriptions-item>

          <el-descriptions-item label="源地址">
            <span :style="{ fontFamily: 'monospace' }">
              {{ selectedItem.srcIP }}:{{ selectedItem.srcPort }}
            </span>
          </el-descriptions-item>

          <el-descriptions-item label="目标地址">
            <span :style="{ fontFamily: 'monospace' }">
              {{ selectedItem.dstIP }}:{{ selectedItem.dstPort }}
            </span>
          </el-descriptions-item>

          <el-descriptions-item label="Suricata 规则">
            <el-tag type="warning">{{ selectedItem.suricata }}</el-tag>
          </el-descriptions-item>

          <el-descriptions-item label="ATT&CK 战术">
            <el-tooltip :content="selectedItem.tacticName" placement="top">
              <el-tag type="danger">{{ selectedItem.tactic }}</el-tag>
            </el-tooltip>
          </el-descriptions-item>

          <el-descriptions-item label="ATT&CK 技术">
            <el-tooltip :content="selectedItem.techniqueName" placement="top">
              <el-tag type="success">{{ selectedItem.technique }}</el-tag>
            </el-tooltip>
          </el-descriptions-item>

          <el-descriptions-item label="流编号">
            <el-tag>{{ selectedItem.flowNum }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">文件信息</el-divider>
        <el-alert
            :title="`文件名: APT_${selectedItem.apt}-${selectedItem.date.replace(/-/g, '')}-${selectedItem.hash}-${selectedItem.flowNum}_${selectedItem.srcIP}_${selectedItem.srcPort}_${selectedItem.dstIP}_${selectedItem.dstPort}_${selectedItem.suricata}_ttp-${selectedItem.technique}_ta-${selectedItem.tactic}.pcap`"
            type="info"
            :closable="false"
            :style="{ fontFamily: 'monospace', fontSize: '0.8rem' }"
        />
      </div>

      <span slot="footer" class="dialog-footer">
        <el-button @click="showDetailModal = false">关闭</el-button>
        <el-button type="primary" @click="downloadSample(selectedItem)" style="background-color: #4a90e2; border-color: #4a90e2;">
          <i class="el-icon-download"></i>
          下载此样本
        </el-button>
      </span>
    </el-dialog>

    <!-- 下载模态框 -->
    <el-dialog
        :visible.sync="showDownloadModal"
        title="申请数据集访问"
        width="600px"
    >
      <el-steps :active="downloadStep" align-center :style="{ marginBottom: '30px' }">
        <el-step title="填写信息"></el-step>
        <el-step title="提交申请"></el-step>
        <el-step title="等待审核"></el-step>
      </el-steps>

      <el-form v-if="downloadStep === 1" :model="downloadForm" label-width="100px">
        <el-form-item label="姓名" required>
          <el-input v-model="downloadForm.name" placeholder="请输入您的姓名" />
        </el-form-item>

        <el-form-item label="邮箱" required>
          <el-input v-model="downloadForm.email" placeholder="请输入邮箱地址" />
        </el-form-item>

        <el-form-item label="机构" required>
          <el-input v-model="downloadForm.organization" placeholder="请输入所在机构" />
        </el-form-item>

        <el-form-item label="身份" required>
          <el-select v-model="downloadForm.position" placeholder="请选择身份" style="width: 100%">
            <el-option label="研究人员" value="researcher" />
            <el-option label="教师" value="teacher" />
            <el-option label="学生" value="student" />
            <el-option label="工程师" value="engineer" />
            <el-option label="其他" value="other" />
          </el-select>
        </el-form-item>

        <el-form-item label="研究目的" required>
          <el-input
              v-model="downloadForm.purpose"
              type="textarea"
              :rows="3"
              placeholder="请简要描述您的研究目的和使用计划"
          />
        </el-form-item>
      </el-form>

      <div v-else-if="downloadStep === 2" :style="{ textAlign: 'center', padding: '40px 0' }">
        <div :style="{ color: '#10b981', fontSize: '48px', marginBottom: '20px' }">✓</div>
        <h3 :style="{ color: '#2c3e50', marginBottom: '10px' }">申请提交成功</h3>
        <p :style="{ color: '#666', lineHeight: '1.6' }">
          我们已收到您的数据集访问申请<br>
          将在 48 小时内通过邮件回复审核结果
        </p>
      </div>

      <span slot="footer" class="dialog-footer">
        <el-button v-if="downloadStep === 1" @click="showDownloadModal = false">取消</el-button>
        <el-button v-if="downloadStep === 1" type="primary" @click="submitDownloadApplication" style="background-color: #4a90e2; border-color: #4a90e2;">
          提交申请
        </el-button>
        <el-button v-if="downloadStep === 2" type="primary" @click="showDownloadModal = false" style="background-color: #4a90e2; border-color: #4a90e2;">
          完成
        </el-button>
      </span>
    </el-dialog>
  </div>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      currentPage: 'browser',
      searchTerm: '',
      showFilters: true,
      showDetailModal: false,
      showDownloadModal: false,
      selectedItem: null,
      currentPageNum: 1,
      itemsPerPage: 10,
      loading: false,
      downloadStep: 1,
      downloadForm: {
        name: '',
        email: '',
        organization: '',
        position: '',
        purpose: ''
      },
      filters: {
        apt: '',
        dateStart: '',
        dateEnd: '',
        tactic: '',
        technique: '',
        suricata: ''
      },
      pcapData: [
        {
          id: 1,
          apt: "APT10",
          date: "2023-01-30",
          hash: "684888079aaf7ed25e725b55a3695062",
          flowNum: 5,
          srcIP: "192.168.100.23",
          srcPort: 58521,
          dstIP: "37.48.65.148",
          dstPort: 80,
          suricata: "sid-2826183",
          tactic: "TA0011",
          tacticName: "Command and Control",
          technique: "T1041",
          techniqueName: "Exfiltration Over C2 Channel"
        },
        {
          id: 2,
          apt: "APT28",
          date: "2023-03-15",
          hash: "a5f3c2e1b8d94f7e6a1c2b3d4e5f6a7b",
          flowNum: 12,
          srcIP: "10.0.2.45",
          srcPort: 49321,
          dstIP: "205.185.125.103",
          dstPort: 443,
          suricata: "sid-2102130",
          tactic: "TA0001",
          tacticName: "Initial Access",
          technique: "T1566",
          techniqueName: "Phishing"
        },
        {
          id: 3,
          apt: "APT29",
          date: "2023-05-22",
          hash: "b8e3f9c2a1d4e6f7c8b9a0d1e2f3g4h5",
          flowNum: 3,
          srcIP: "172.16.32.108",
          srcPort: 51234,
          dstIP: "185.244.25.197",
          dstPort: 8080,
          suricata: "sid-2824208",
          tactic: "TA0007",
          tacticName: "Discovery",
          technique: "T1082",
          techniqueName: "System Information Discovery"
        },
        {
          id: 4,
          apt: "APT32",
          date: "2023-07-11",
          hash: "c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
          flowNum: 8,
          srcIP: "192.168.15.201",
          srcPort: 60001,
          dstIP: "45.14.52.38",
          dstPort: 53,
          suricata: "sid-2821781",
          tactic: "TA0010",
          tacticName: "Exfiltration",
          technique: "T1020",
          techniqueName: "Automated Exfiltration"
        },
        {
          id: 5,
          apt: "Lazarus",
          date: "2023-09-05",
          hash: "d6e5f4c3b2a1f0e9d8c7b6a5f4e3d2c1",
          flowNum: 15,
          srcIP: "10.10.50.75",
          srcPort: 54321,
          dstIP: "194.145.63.205",
          dstPort: 22,
          suricata: "sid-2819886",
          tactic: "TA0008",
          tacticName: "Lateral Movement",
          technique: "T1021",
          techniqueName: "Remote Services"
        }
      ]
    }
  },
  computed: {
    filteredData() {
      let result = this.pcapData;
      
      // 搜索过滤
      if (this.searchTerm) {
        const term = this.searchTerm.toLowerCase();
        result = result.filter(item => 
          item.hash.toLowerCase().includes(term) ||
          item.srcIP.includes(term) ||
          item.dstIP.includes(term) ||
          item.apt.toLowerCase().includes(term)
        );
      }
      
      // APT组织过滤
      if (this.filters.apt) {
        result = result.filter(item => item.apt === this.filters.apt);
      }
      
      // 日期范围过滤
      if (this.filters.dateStart) {
        result = result.filter(item => item.date >= this.filters.dateStart);
      }
      
      if (this.filters.dateEnd) {
        result = result.filter(item => item.date <= this.filters.dateEnd);
      }
      
      // 战术过滤
      if (this.filters.tactic) {
        result = result.filter(item => item.tactic === this.filters.tactic);
      }
      
      // 技术过滤
      if (this.filters.technique) {
        result = result.filter(item => item.technique === this.filters.technique);
      }
      
      // Suricata ID过滤
      if (this.filters.suricata) {
        result = result.filter(item => item.suricata.includes(this.filters.suricata));
      }
      
      return result;
    },
    paginatedData() {
      const start = (this.currentPageNum - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return this.filteredData.slice(start, end);
    },
    aptOptions() {
      return [...new Set(this.pcapData.map(d => d.apt))];
    },
    tacticOptions() {
      return [...new Set(this.pcapData.map(d => d.tacticName))];
    },
    aptCount() {
      return new Set(this.filteredData.map(d => d.apt)).size;
    },
    dateRange() {
      if (this.filteredData.length === 0) return '-';
      const dates = this.filteredData.map(d => d.date).sort();
      return `${dates[0]} ~ ${dates[dates.length - 1]}`;
    },
    techniqueOptions() {
      return [...new Set(this.pcapData.map(d => d.techniqueName))];
    }
  },
  methods: {
    performSearch() {
      this.currentPageNum = 1;
    },
    toggleFilters() {
      this.showFilters = !this.showFilters;
    },
    applyFilters() {
      this.currentPageNum = 1;
    },
    resetFilters() {
      this.searchTerm = '';
      this.filters = {
        apt: '',
        dateStart: '',
        dateEnd: '',
        tactic: '',
        technique: '',
        suricata: ''
      };
      this.currentPageNum = 1;
    },
    showDetail(item) {
      this.selectedItem = item;
      this.showDetailModal = true;
    },
    downloadSample(item) {
      this.$message.success(`开始下载 ${item.apt} 样本`);
    },
    showDownloadModal() {
      this.showDownloadModal = true;
      this.downloadStep = 1;
    },
    submitDownloadApplication() {
      this.downloadStep = 2;
    },
    exportData() {
      this.$message.info('导出功能开发中...');
    },
    getAptColor(apt) {
      const colors = {
        'APT10': '#ef4444',
        'APT28': '#3b82f6',
        'APT29': '#8b5cf6',
        'APT32': '#f59e0b',
        'Lazarus': '#10b981'
      };
      return colors[apt] || '#6b7280';
    },
    handleSizeChange(val) {
      this.itemsPerPage = val;
      this.currentPageNum = 1;
    },
    handleCurrentChange(val) {
      this.currentPageNum = val;
    }
  }
}
</script>