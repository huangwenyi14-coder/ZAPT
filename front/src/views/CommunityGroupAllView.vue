<template>
  <div class="group-all-container">
    <el-page-header @back="goBack" content="全部小组">
    </el-page-header>

    <div class="search-section">
      <el-input
        v-model="searchKeyword"
        placeholder="请输入小组名称进行搜索"
        clearable
        @clear="searchGroups"
        @keyup.enter.native="searchGroups"
        style="width: 300px; margin-right: 20px;"
      >
        <i slot="prefix" class="el-input__icon el-icon-search"></i>
      </el-input>
      <el-button type="primary" @click="searchGroups">搜索</el-button>
    </div>

    <div class="main-content">
      <div class="groups-section">
        <h2>所有小组</h2>
        <el-card v-for="group in groups" :key="group.id" class="group-card">
          <div class="group-info">
            <div class="group-avatar">
              <img v-if="group.avatar && group.avatar.startsWith('http')" :src="group.avatar" class="group-avatar-img" />
              <div v-else class="avatar-placeholder">👥</div>
            </div>
            <div class="group-details">
              <h3>{{ group.name }}</h3>
              <p>{{ group.description }}</p>
              <div class="group-stats">
                <span>成员: {{ group.members }}</span>
                <span>话题: {{ group.topics }}</span>
                <span>创建时间: {{ group.createTime }}</span>
              </div>
            </div>
            <el-button type="primary" @click="viewGroup(group.id)">查看</el-button>
          </div>
        </el-card>
        
        <!-- 分页 -->
        <div class="pagination-container" v-if="pagination.total > 0">
          <el-pagination
            @size-change="handleSizeChange"
            @current-change="handlePageChange"
            :current-page="pagination.pageNum"
            :page-sizes="[5, 10, 20, 50]"
            :page-size="pagination.pageSize"
            :total="pagination.total"
            layout="total, sizes, prev, pager, next, jumper"
            background>
          </el-pagination>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { groupApi } from '@/utils/api'

export default {
  name: 'CommunityGroupAllView',
  data() {
    return {
      groups: [],
      searchKeyword: '',
      pagination: {
        pageNum: 1,
        pageSize: 5,
        total: 0
      }
    }
  },
  created() {
    this.loadGroups()
  },
  methods: {
    async loadGroups() {
      try {
        const res = await groupApi.getGroupsByPage(
          this.pagination.pageNum, 
          this.pagination.pageSize, 
          this.searchKeyword
        )
        if (res.code === '200') {
          this.groups = res.data.records.map(group => ({
            id: group.id,
            name: group.name,
            avatar: group.avatar || '',
            description: group.description,
            members: group.memberCount || 0,
            topics: group.topicCount || 0,
            createTime: group.createdAt ? new Date(group.createdAt).toLocaleDateString() : ''
          }))
          this.pagination.total = res.data.total
          this.pagination.pageNum = res.data.pageNum
          this.pagination.pageSize = res.data.pageSize
        } else {
          this.$message.error(res.msg || '获取小组列表失败')
        }
      } catch (err) {
        this.$message.error('获取小组列表失败: ' + err.message)
      }
    },
    handleSizeChange(pageSize) {
      this.pagination.pageSize = pageSize
      this.pagination.pageNum = 1
      this.loadGroups()
    },
    handlePageChange(pageNum) {
      this.pagination.pageNum = pageNum
      this.loadGroups()
    },
    searchGroups() {
      this.pagination.pageNum = 1
      this.loadGroups()
    },
    goBack() {
      this.$router.push('/community/home').catch(err => {
        if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
          console.error('路由跳转错误:', err);
        }
      });
    },
    viewGroup(id) {
      this.$router.push(`/community/group/${id}`).catch(err => {
        if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
          console.error('路由跳转错误:', err);
        }
      });
    }
  }
}
</script>

<style scoped>
.group-all-container {
  padding: 20px;
}

.search-section {
  margin-bottom: 20px;
  display: flex;
  align-items: center;
}

.main-content {
  display: flex;
  margin-top: 20px;
  gap: 20px;
}

.groups-section {
  flex: 1;
}

.group-card {
  margin-bottom: 15px;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  transition: box-shadow 0.3s ease;
}

.group-card:hover {
  box-shadow: 0 4px 12px rgba(74, 144, 226, 0.15);
}

.group-info {
  display: flex;
  align-items: center;
  gap: 15px;
}

.group-avatar {
  width: 60px;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f5f7fa;
  border-radius: 50%;
}

.group-avatar-img {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  object-fit: cover;
}

.avatar-placeholder {
  font-size: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
}

.group-details {
  flex: 1;
}

.group-details h3 {
  color: #2c3e50;
  margin-bottom: 5px;
}

.group-details p {
  color: #7f8c8d;
  margin-bottom: 10px;
  font-size: 14px;
}

.group-stats {
  display: flex;
  gap: 20px;
  margin-top: 10px;
  color: #7f8c8d;
  font-size: 13px;
}

.groups-section h2 {
  color: #2c3e50;
  border-bottom: 2px solid #4a90e2;
  padding-bottom: 10px;
  margin-bottom: 20px;
}

.pagination-container {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.el-page-header {
  margin-bottom: 20px;
}

.el-page-header__content {
  color: #2c3e50;
  font-weight: bold;
}

.el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
}
</style>