<template>
  <div class="community-container">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-content">
        <h1 class="hero-title">ZAPT 社区</h1>
        <p class="hero-subtitle">恶意流量检测交流平台</p>
      </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
      <!-- 三个选项 -->
      <div class="options-section">
        <el-row :gutter="20" class="button-row">
          <el-col :span="8">
            <el-button class="option-button" @click="createGroup">
              <i class="el-icon-plus option-icon"></i>
              <span>创建小组</span>
            </el-button>
          </el-col>
          <el-col :span="8">
            <el-button class="option-button" @click="viewMyGroups">
              <i class="el-icon-user option-icon"></i>
              <span>个人信息</span>
            </el-button>
          </el-col>
          <el-col :span="8">
            <el-button class="option-button" @click="viewAllGroups">
              <i class="el-icon-view option-icon"></i>
              <span>查看全部小组</span>
            </el-button>
          </el-col>
        </el-row>
      </div>

      <!-- 推荐小组 -->
      <div class="recommended-section">
        <h2>推荐小组</h2>
        <el-row :gutter="20">
          <el-col :span="8" v-for="group in recommendedGroups" :key="group.id">
            <el-card class="group-card" @click.native="viewGroup(group.id)">
              <div class="group-info">
                <div class="group-avatar">
                  <img v-if="group.avatar && group.avatar.startsWith('http')" :src="group.avatar" class="group-avatar-img" />
                  <span v-else>{{ group.avatar }}</span>
                </div>
                <div class="group-name">{{ group.name }}</div>
                <div class="group-desc">{{ group.description }}</div>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </div>

      <!-- 最新话题和最新成立小组 -->
      <div class="bottom-section">
        <el-row :gutter="20">
          <el-col :span="18">
            <div class="latest-topics">
              <h2>最新话题</h2>
              <el-card v-for="topic in latestTopics" :key="topic.id" class="topic-card" @click.native="viewTopic(topic.id)">
                <div class="topic-title">{{ topic.title }}</div>
                <div class="topic-meta">
                  <span><i class="el-icon-folder"></i> 小组：{{ topic.groupName }}</span>
                  <span><i class="el-icon-user"></i> 作者：{{ topic.authorName }}</span>
                  <span><i class="el-icon-chat-dot-round"></i> 评论：{{ topic.commentCount }}</span>
                  <span><i class="el-icon-thumb"></i> 点赞：{{ topic.likeCount }}</span>
                </div>
              </el-card>
            </div>
          </el-col>
          <el-col :span="6">
            <div class="new-groups">
              <h2>最新成立小组</h2>
              <el-card v-for="group in newGroups" :key="group.id" class="group-card small" @click.native="viewGroup(group.id)">
                <div class="group-info horizontal">
                  <div class="group-avatar small">
                    <img v-if="group.avatar && group.avatar.startsWith('http')" :src="group.avatar" class="group-avatar-img" />
                    <span v-else>{{ group.avatar }}</span>
                  </div>
                  <div class="group-name small">{{ group.name }}</div>
                </div>
              </el-card>
            </div>
          </el-col>
        </el-row>
      </div>
    </div>

    <!-- 创建小组对话框 -->
    <el-dialog title="创建小组" :visible.sync="showCreateGroupDialog" width="500px">
      <el-form :model="newGroup" :rules="groupRules" ref="groupForm" label-width="80px">
        <el-form-item label="小组名称" prop="name">
          <el-input v-model="newGroup.name" placeholder="请输入小组名称"></el-input>
        </el-form-item>
        <el-form-item label="小组描述" prop="description">
          <el-input 
            type="textarea" 
            :rows="3" 
            placeholder="请输入小组描述" 
            v-model="newGroup.description">
          </el-input>
        </el-form-item>
        <el-form-item label="小组图标" prop="avatar">
          <el-upload
              action="/api/file/upload"
              :headers="{token: user.token}"
              :on-success="handleAvatarUploadSuccess"
              class="avatar-uploader">
            <img v-if="newGroup.avatar" :src="newGroup.avatar" class="avatar">
            <i v-else class="el-icon-plus avatar-uploader-icon"></i>
          </el-upload>
        </el-form-item>
      </el-form>
      <span slot="footer" class="dialog-footer">
        <el-button @click="showCreateGroupDialog = false">取 消</el-button>
        <el-button type="primary" @click="submitGroup" style="background-color: #4a90e2; border-color: #4a90e2;">创 建</el-button>
      </span>
    </el-dialog>
  </div>
</template>

<script>
import { groupApi, topicApi } from '@/utils/api'

export default {
  name: 'Community',
  data() {
    return {
      showCreateGroupDialog: false,
      newGroup: {
        name: '',
        description: '',
        avatar: ''
      },
      groupRules: {
        name: [
          { required: true, message: '请输入小组名称', trigger: 'blur' }
        ],
        description: [
          { required: true, message: '请输入小组描述', trigger: 'blur' }
        ]
      },
      recommendedGroups: [],
      latestTopics: [],
      newGroups: [],
      user: localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {}
    }
  },
  created() {
    this.loadRecommendedGroups()
    this.loadLatestTopics()
    this.loadNewGroups()
  },
  methods: {
    createGroup() {
      this.showCreateGroupDialog = true
      this.$nextTick(() => {
        this.$refs.groupForm.resetFields()
        this.newGroup.avatar = '' // 清空头像
      })
    },
    handleAvatarUploadSuccess(res) {
      console.log(res)
      // 检查响应结构并设置头像URL
      if (res && res.code === '200' && res.data) {
        this.newGroup.avatar = res.data
      } else if (res && typeof res === 'string') {
        this.newGroup.avatar = res
      } else if (res && res.url) {
        this.newGroup.avatar = res.url
      }
    },
    async submitGroup() {
      this.$refs.groupForm.validate(async (valid) => {
        if (valid) {
          try {
            // 获取当前用户ID（应该从登录信息中获取）
            const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
            const creatorId = currentUser.id || 1
            
            const groupData = {
              name: this.newGroup.name,
              description: this.newGroup.description,
              avatar: this.newGroup.avatar || '',
              creatorId: creatorId
            }
            
            const res = await groupApi.saveGroup(groupData)
            if (res.code === '200') {
              this.$message.success('小组创建成功！')
              this.showCreateGroupDialog = false
              
              // 创建成功后自动刷新推荐小组
              this.loadRecommendedGroups()
              
              // 如果返回了创建的小组ID，则自动跳转到小组详情页
              if (res.data && res.data.id) {
                // 自动加入小组
                await this.autoJoinGroup(res.data.id, creatorId);
                // 跳转到小组详情页
                this.$router.push(`/community/group/${res.data.id}`).catch(err => {
                  if (err.name !== 'NavigationDuplicated') {
                    throw err;
                  }
                });
              }
            } else {
              this.$message.error(res.msg || '创建小组失败')
            }
          } catch (err) {
            this.$message.error('创建小组失败: ' + err.message)
          }
        }
      })
    },
    // 自动加入小组（创建者自动成为小组成员）
    async autoJoinGroup(groupId, userId) {
      try {
        const groupMemberData = {
          groupId: groupId,
          userId: userId,
          role: 'moderator' // 创建者默认为管理员角色
        };
        
        // 这里可以调用加入小组的API，如果有的话
        // 暂时先不实现，因为可能在后端已经处理了
      } catch (err) {
        console.log('自动加入小组失败:', err);
      }
    },
    async loadRecommendedGroups() {
      try {
        const res = await groupApi.getAllGroups()
        if (res.code === '200') {
          this.recommendedGroups = res.data.slice(0, 3).map(group => ({
            id: group.id,
            name: group.name,
            description: group.description,
            avatar: group.avatar || '👥'
          })) // 取前3个作为推荐
        } else {
          // 不再显示错误消息，避免未登录时频繁弹窗
          console.log('获取推荐小组失败:', res.msg)
        }
      } catch (err) {
        // 不再显示错误消息，避免未登录时频繁弹窗
        console.log('获取推荐小组失败:', err.message)
      }
    },
    async loadLatestTopics() {
      try {
        // 从后端加载热门话题
        const res = await topicApi.getTopTopics()
        if (res.code === '200') {
          // 处理返回的热门话题数据
          this.latestTopics = res.data.map(topic => ({
            id: topic.id,
            title: topic.title,
            groupName: topic.groupName || '默认小组',
            authorName: topic.authorName || '匿名用户',
            commentCount: topic.commentCount || 0,
            likeCount: topic.likeCount || 0
          }))
        } else {
          // 不再显示错误消息，避免未登录时频繁弹窗
          console.log('获取热门话题失败:', res.msg)
        }
      } catch (err) {
        // 不再显示错误消息，避免未登录时频繁弹窗
        console.log('获取热门话题失败:', err.message)
      }
    },
    async loadNewGroups() {
      try {
        // 从后端加载最新成立小组
        const res = await groupApi.getLatestGroups()
        if (res.code === '200') {
          // 按创建时间排序并取前几个作为最新成立小组显示
          this.newGroups = res.data.map(group => ({
            id: group.id,
            name: group.name,
            avatar: group.avatar || '👥'
          }))
        } else {
          // 不再显示错误消息，避免未登录时频繁弹窗
          console.log('获取最新小组失败:', res.msg)
        }
      } catch (err) {
        // 不再显示错误消息，避免未登录时频繁弹窗
        console.log('获取最新小组失败:', err.message)
      }
    },
    viewMyGroups() {
      this.$router.push('/community/me').catch(err => {
        if (err.name !== 'NavigationDuplicated') {
          throw err;
        }
      });
    },
    viewAllGroups() {
      this.$router.push('/community/all').catch(err => {
        if (err.name !== 'NavigationDuplicated') {
          throw err;
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
    viewTopic(id) {
      this.$router.push(`/community/topic/${id}`).catch(err => {
        if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
          console.error('路由跳转错误:', err);
        }
      });
    }
  }
}
</script>

<style scoped>
.community-container {
  min-height: 100vh;
  background: white;
}

.hero-section {
  background: linear-gradient(135deg, #4a90e2 0%, #764ba2 100%);
  color: white;
  padding: 80px 20px;
  text-align: center;
}

.hero-content {
  max-width: 800px;
  margin: 0 auto;
}

.hero-title {
  font-size: 3rem;
  font-weight: 700;
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
  padding: 80px 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.options-section {
  margin-bottom: 40px;
}

.button-row {
  display: flex;
  justify-content: center;
}

.option-button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 20px;
  font-size: 1rem;
  font-weight: 500;
  border-radius: 20px;
  background: #f0f2f5;
  border: 1px solid #dcdfe6;
  color: #606266;
  transition: all 0.3s ease;
  width: fit-content;
  margin: 0 auto;
}

.option-button:hover {
  background: #4a90e2;
  color: white;
  border-color: #4a90e2;
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.option-icon {
  font-size: 1.2rem;
}

.recommended-section {
  margin-bottom: 40px;
}

.group-card {
  cursor: pointer;
  transition: all 0.3s ease;
  height: 150px; /* 增加推荐小组卡片的高度 */
}

.group-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.group-info {
  text-align: center;
  height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.group-info.horizontal {
  flex-direction: row;
  justify-content: flex-start;
  align-items: center;
  text-align: left;
}

.group-avatar {
  width: 48px;
  height: 48px;
  margin: 0 auto 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
}

.group-avatar.small {
  width: 32px;
  height: 32px;
  font-size: 16px;
  margin: 0 10px 0 0;
}

.group-avatar-img {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  object-fit: cover;
}

.group-name {
  font-size: 1.2rem;
  font-weight: 600;
  margin-bottom: 5px;
}

.group-name.small {
  font-size: 1rem;
  font-weight: 500;
  margin: 0;
}

.group-desc {
  color: #666;
  font-size: 0.8rem; /* 减小简介字体 */
  display: -webkit-box;
  -webkit-line-clamp: 2; /* 限制最多两行 */
  -webkit-box-orient: vertical;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 1.4;
}

.group-stats {
  display: flex;
  justify-content: space-around;
  color: #999;
  font-size: 0.8rem;
  margin-top: auto;
}

.bottom-section {
  margin-top: 40px;
}

.latest-topics, .new-groups {
  background: #f5f7fa;
  border-radius: 8px;
  padding: 20px;
}

.topic-card {
  margin-bottom: 15px;
  cursor: pointer;
}

.topic-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.topic-title {
  font-weight: 600;
  margin-bottom: 10px;
}

.topic-meta {
  display: flex;
  justify-content: space-between;
  color: #7f8c8d;
  font-size: 0.8rem;
}

.group-details {
  display: flex;
  flex-direction: column;
  flex-grow: 1;
}

.group-date {
  color: #999;
  font-size: 0.8rem;
  margin-top: 5px;
}

.new-groups .group-card {
  margin-bottom: 10px;
  height: 60px; /* 降低最新小组卡片的高度 */
}
</style>