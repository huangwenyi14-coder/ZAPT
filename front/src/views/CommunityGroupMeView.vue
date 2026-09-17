<template>
  <div class="group-me-container">
    <el-page-header @back="goBack" content="个人信息">
    </el-page-header>

    <div class="main-content">
      <!-- 个人信息统计 -->
      <div class="stats-section">
        <el-row :gutter="20">
          <el-col :span="12">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-value">{{ topicCount }}</div>
                <div class="stat-label">话题数量</div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="12">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-value">{{ groupCount }}</div>
                <div class="stat-label">参与小组</div>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </div>

      <!-- 我的话题和参加的小组 -->
      <div class="content-section">
        <div class="content-header">
          <el-button :type="activeTab === 'topics' ? 'primary' : ''" @click="switchTab('topics')">我的话题</el-button>
          <el-button :type="activeTab === 'groups' ? 'primary' : ''" @click="switchTab('groups')">参加小组</el-button>
        </div>

        <div class="content-body">
          <!-- 我写的话题 -->
          <div v-if="activeTab === 'topics'" class="topics-content">
            <el-card v-for="topic in myTopics" :key="topic.id" class="topic-card">
              <div class="topic-header">
                <h3 @click="viewTopic(topic.id)" class="topic-title">{{ topic.title }}</h3>
                <el-button type="danger" size="mini" @click="deleteTopic(topic.id)">删除</el-button>
              </div>
              <div class="topic-meta">
                <span>{{ topic.date }}</span>
                <span>👍 {{ topic.likes }}</span>
                <span>{{ topic.replies }} 回复</span>
              </div>
            </el-card>
            
            <!-- 话题分页 -->
            <div class="pagination-container" v-if="topicPagination.total > 0">
              <el-pagination
                @size-change="handleTopicSizeChange"
                @current-change="handleTopicCurrentChange"
                :current-page="topicPagination.pageNum"
                :page-sizes="[5, 10, 20, 50]"
                :page-size="topicPagination.pageSize"
                :total="topicPagination.total"
                layout="total, sizes, prev, pager, next, jumper"
                background>
              </el-pagination>
            </div>
          </div>

          <!-- 参加的小组 -->
          <div v-else class="groups-content">
            <el-card v-for="group in myGroups" :key="group.id" class="group-card" @click.native="viewGroup(group.id)">
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
                  </div>
                </div>
              </div>
            </el-card>
            
            <!-- 小组分页 -->
            <div class="pagination-container" v-if="groupPagination.total > 0">
              <el-pagination
                @size-change="handleGroupSizeChange"
                @current-change="handleGroupCurrentChange"
                :current-page="groupPagination.pageNum"
                :page-sizes="[5, 10, 20, 50]"
                :page-size="groupPagination.pageSize"
                :total="groupPagination.total"
                layout="total, sizes, prev, pager, next, jumper"
                background>
              </el-pagination>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { groupApi, topicApi, groupMemberApi } from '@/utils/api'

export default {
  name: 'CommunityGroupMeView',
  data() {
    return {
      topicCount: 0,
      groupCount: 0,
      activeTab: 'topics',
      myTopics: [],
      myGroups: [],
      topicPagination: {
        pageNum: 1,
        pageSize: 5,
        total: 0
      },
      groupPagination: {
        pageNum: 1,
        pageSize: 5,
        total: 0
      }
    }
  },
  created() {
    this.loadUserStats()
    this.loadMyTopics()
    this.loadMyGroups()
  },
  methods: {
    async loadUserStats() {
      try {
        // 获取当前用户ID（应该从登录信息中获取）
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
        const userId = currentUser.id || 1
        
        // 从话题表和小组成员表直接获取统计信息
        const topicRes = await topicApi.getTopicsByAuthorId(userId);
        const groupRes = await groupMemberApi.getGroupsByUserId(userId);
        
        if (topicRes.code === '200') {
          this.topicCount = topicRes.data.length || 0;
        } else {
          this.topicCount = 0;
        }
        
        if (groupRes.code === '200') {
          this.groupCount = groupRes.data.length || 0;
        } else {
          this.groupCount = 0;
        }
      } catch (err) {
        this.$message.error('获取用户统计数据失败: ' + err.message)
        // 使用默认值0
        this.topicCount = 0
        this.groupCount = 0
      }
    },
    async loadMyTopics() {
      try {
        // 获取当前用户ID（应该从登录信息中获取）
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
        const userId = currentUser.id || 1
        const res = await topicApi.getTopicsByAuthorId(userId)
        if (res.code === '200') {
          // 对当前用户的所有话题进行前端分页
          const allTopics = res.data;
          const start = (this.topicPagination.pageNum - 1) * this.topicPagination.pageSize;
          const end = start + this.topicPagination.pageSize;
          const pagedTopics = allTopics.slice(start, end);
          
          this.myTopics = pagedTopics.map(topic => ({
            id: topic.id,
            title: topic.title,
            date: topic.createdAt ? new Date(topic.createdAt).toLocaleDateString() : '',
            likes: topic.likeCount || 0,
            replies: topic.commentCount || 0
          }))
          this.topicPagination.total = allTopics.length
        } else {
          this.$message.error(res.msg || '获取话题列表失败')
        }
      } catch (err) {
        this.$message.error('获取话题列表失败: ' + err.message)
      }
    },
    async loadMyGroups() {
      try {
        // 获取当前用户ID（应该从登录信息中获取）
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
        const userId = currentUser.id || 1
        
        // 先获取用户参与的小组ID列表
        const memberRes = await groupMemberApi.getGroupsByUserId(userId)
        if (memberRes.code === '200') {
          // 分页处理
          const allGroupIds = memberRes.data.map(member => member.groupId)
          const start = (this.groupPagination.pageNum - 1) * this.groupPagination.pageSize
          const end = start + this.groupPagination.pageSize
          const pagedGroupIds = allGroupIds.slice(start, end)
          
          // 获取小组详细信息
          const groupPromises = pagedGroupIds.map(groupId => groupApi.getGroupById(groupId))
          const groupResults = await Promise.all(groupPromises)
          
          this.myGroups = groupResults
            .filter(result => result.code === '200')
            .map(result => result.data)
            .map(group => ({
              id: group.id,
              name: group.name,
              avatar: group.avatar || '',
              description: group.description,
              members: group.memberCount || 0,
              topics: group.topicCount || 0
            }))
            
          this.groupPagination.total = allGroupIds.length
        } else {
          this.$message.error(memberRes.msg || '获取小组列表失败')
        }
      } catch (err) {
        this.$message.error('获取小组列表失败: ' + err.message)
      }
    },
    handleTopicSizeChange(pageSize) {
      this.topicPagination.pageSize = pageSize
      this.topicPagination.pageNum = 1
      this.loadMyTopics()
    },
    handleTopicCurrentChange(pageNum) {
      this.topicPagination.pageNum = pageNum
      this.loadMyTopics()
    },
    handleGroupSizeChange(pageSize) {
      this.groupPagination.pageSize = pageSize
      this.groupPagination.pageNum = 1
      this.loadMyGroups()
    },
    handleGroupCurrentChange(pageNum) {
      this.groupPagination.pageNum = pageNum
      this.loadMyGroups()
    },
    goBack() {
      this.$router.push('/community/home').catch(err => {
        if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
          console.error('路由跳转错误:', err);
        }
      });
    },
    switchTab(tab) {
      this.activeTab = tab;
    },
    viewTopic(id) {
      this.$router.push(`/community/topic/${id}`).catch(err => {
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
    },
    deleteTopic(id) {
      this.$confirm('此操作将永久删除该话题及其所有相关数据（评论、点赞等）, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(async () => {
        try {
          const res = await topicApi.deleteTopic(id);
          if (res.code === '200') {
            this.$message.success('删除成功!');
            // 重新加载数据
            this.loadUserStats();
            this.loadMyTopics();
          } else {
            this.$message.error(res.msg || '删除失败');
          }
        } catch (err) {
          this.$message.error('删除失败: ' + err.message);
        }
      }).catch(() => {
        this.$message.info('已取消删除');
      });
    }
  }
}
</script>

<style scoped>
.group-me-container {
  padding: 20px;
}

.stats-section {
  margin-bottom: 30px;
}

.el-row {
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  transition: box-shadow 0.3s ease;
}

.stat-card:hover {
  box-shadow: 0 4px 12px rgba(74, 144, 226, 0.15);
}

.stat-content {
  padding: 20px 0;
}

.stat-value {
  font-size: 2rem;
  font-weight: bold;
  color: #4a90e2;
}

.stat-label {
  margin-top: 10px;
  color: #7f8c8d;
}

.content-header {
  margin-bottom: 20px;
}

.content-header .el-button {
  margin-right: 10px;
  border-color: #4a90e2;
  color: #4a90e2;
}

.content-header .el-button:hover {
  background-color: #f0f8ff;
}

.content-header .el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
  color: white;
}

.topic-card, .group-card {
  margin-bottom: 15px;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  transition: box-shadow 0.3s ease;
}

.topic-card:hover, .group-card:hover {
  box-shadow: 0 4px 12px rgba(74, 144, 226, 0.15);
}

.topic-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.topic-title {
  color: #2c3e50;
  margin-bottom: 10px;
  cursor: pointer;
}

.topic-card p, .group-card p {
  color: #7f8c8d;
  margin-bottom: 15px;
  font-size: 14px;
}

.group-info {
  display: flex;
  align-items: center;
  gap: 15px;
}

.group-avatar {
  width: 50px;
  height: 50px;
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
  font-size: 1.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
}

.group-stats {
  display: flex;
  gap: 20px;
  margin-top: 10px;
  color: #7f8c8d;
  font-size: 13px;
}

.topic-meta {
  display: flex;
  gap: 20px;
  color: #7f8c8d;
  margin-top: 10px;
  font-size: 13px;
  border-top: 1px solid #eee;
  padding-top: 10px;
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
</style>