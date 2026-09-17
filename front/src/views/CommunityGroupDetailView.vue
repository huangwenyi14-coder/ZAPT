<template>
  <div class="group-detail-container">
    <el-page-header @back="goBack" content="小组详情">
    </el-page-header>

    <!-- 小组介绍 -->
    <div class="group-header">
      <el-card>
        <div class="group-info">
          <div class="group-avatar">
            <img v-if="groupInfo.avatar && groupInfo.avatar.startsWith('http')" :src="groupInfo.avatar" class="group-avatar-img" />
            <div v-else class="avatar-placeholder">👥</div>
          </div>
          <div class="group-details">
            <h2>{{ groupInfo.name }}</h2>
            <p>{{ groupInfo.description }}</p>
            <div class="group-stats">
              <span>成员: {{ groupInfo.members }}</span>
              <span>话题: {{ groupInfo.topics }}</span>
              <span>创建时间: {{ groupInfo.createTime }}</span>
            </div>
          </div>
          <div class="group-actions">
            <el-button v-if="!isMember" type="primary" @click="joinGroup">加入小组</el-button>
            <div v-else>
              <el-button type="primary" @click="shareGroup">分享</el-button>
              <el-button v-if="canDisband" type="danger" @click="disbandGroup">解散小组</el-button>
              <el-button v-else type="danger" @click="leaveGroup">退出小组</el-button>
              <el-button type="primary" @click="createTopic">发表话题</el-button>
            </div>
          </div>
        </div>
      </el-card>
    </div>

    <!-- 话题列表和成员列表 -->
    <div class="main-content">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="话题列表" name="topics">
          <div class="topics-section">
            <el-card v-for="topic in topics" :key="topic.id" class="topic-card" @click.native="viewTopic(topic.id)">
              <h3>{{ topic.title }}</h3>
              <div class="topic-meta">
                <span>{{ topic.author }}</span>
                <span>{{ topic.date }}</span>
                <span>👍 {{ topic.likes }}</span>
                <span>{{ topic.replies }} 回复</span>
              </div>
            </el-card>
            
            <!-- 分页 -->
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
        </el-tab-pane>
        <el-tab-pane label="成员列表" name="members">
          <div class="members-section">
            <!-- 成员列表 -->
            <el-row :gutter="20">
              <el-col :span="8" v-for="member in members" :key="member.id">
                <el-card class="member-card">
                  <div class="member-info">
                    <div class="member-avatar">
                      <img v-if="member.avatar && member.avatar.startsWith('http')" :src="member.avatar" class="member-avatar-img" />
                      <div v-else class="avatar-placeholder">👤</div>
                    </div>
                    <div class="member-details">
                      <h4>{{ member.name }}</h4>
                      <p>{{ member.role }}</p>
                    </div>
                  </div>
                </el-card>
              </el-col>
            </el-row>
            
            <!-- 成员分页 -->
            <div class="pagination-container" v-if="memberPagination.total > 0">
              <el-pagination
                @size-change="handleMemberSizeChange"
                @current-change="handleMemberCurrentChange"
                :current-page="memberPagination.pageNum"
                :page-sizes="[6, 12, 18, 24]"
                :page-size="memberPagination.pageSize"
                :total="memberPagination.total"
                layout="total, sizes, prev, pager, next, jumper"
                background>
              </el-pagination>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>

    <!-- 发表话题对话框 -->
    <el-dialog title="发表话题" :visible.sync="showCreateTopicDialog" width="800px">
      <el-form :model="newTopic" :rules="topicRules" ref="topicForm" label-width="80px">
        <el-form-item label="话题标题" prop="title">
          <el-input v-model="newTopic.title" placeholder="请输入话题标题"></el-input>
        </el-form-item>
        <el-form-item label="话题内容" prop="content">
          <quill-editor
            v-model="newTopic.content"
            :options="editorOption"
            style="height: 300px; margin-bottom: 100px;">
          </quill-editor>
        </el-form-item>
      </el-form>
      <span slot="footer" class="dialog-footer">
        <el-button @click="showCreateTopicDialog = false">取 消</el-button>
        <el-button type="primary" @click="submitTopic">发 表</el-button>
      </span>
    </el-dialog>
  </div>
</template>

<script>
import { groupApi, topicApi, groupMemberApi } from '@/utils/api'
import { quillEditor } from 'vue-quill-editor'
import 'quill/dist/quill.core.css'
import 'quill/dist/quill.snow.css'
import 'quill/dist/quill.bubble.css'

export default {
  name: 'CommunityGroupDetailView',
  components: {
    quillEditor
  },
  data() {
    return {
      activeTab: 'topics',
      isMember: false,
      userRole: '', // 用户在小组中的角色
      canDisband: false, // 是否可解散小组(创建者或管理员)
      showCreateTopicDialog: false,
      newTopic: {
        title: '',
        content: ''
      },
      editorOption: {
        modules: {
          toolbar: [
            ['bold', 'italic', 'underline', 'strike'],
            ['blockquote', 'code-block'],
            [{ 'header': 1 }, { 'header': 2 }],
            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
            [{ 'script': 'sub'}, { 'script': 'super' }],
            [{ 'indent': '-1'}, { 'indent': '+1' }],
            [{ 'direction': 'rtl' }],
            [{ 'size': ['small', false, 'large', 'huge'] }],
            [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
            [{ 'color': [] }, { 'background': [] }],
            [{ 'font': [] }],
            [{ 'align': [] }],
            ['clean'],
            ['link', 'image', 'video']
          ]
        },
        theme: 'snow',
        placeholder: '请输入话题内容...'
      },
      topicRules: {
        title: [
          { required: true, message: '请输入话题标题', trigger: 'blur' }
        ],
        content: [
          { required: true, message: '请输入话题内容', trigger: 'blur' }
        ]
      },
      groupInfo: {
        id: 0,
        name: '',
        avatar: '',
        description: '',
        members: 0,
        topics: 0,
        createTime: ''
      },
      topics: [],
      members: [],
      topicPagination: {
        pageNum: 1,
        pageSize: 5,
        total: 0
      },
      memberPagination: {
        pageNum: 1,
        pageSize: 6,
        total: 0
      }
    }
  },
  created() {
    const groupId = this.$route.params.id
    if (groupId) {
      this.loadGroupInfo(groupId)
      this.loadTopics(groupId)
      this.loadMembers(groupId)
      this.checkIsMember(groupId)
    }
  },
  methods: {
    createTopic() {
      this.showCreateTopicDialog = true
      this.$nextTick(() => {
        this.$refs.topicForm.resetFields()
        // 重置富文本编辑器内容
        this.newTopic.content = ''
      })
    },
    shareGroup() {
      const url = window.location.href;
      navigator.clipboard.writeText(url).then(() => {
        this.$message.success('链接已复制到剪贴板');
      }).catch(err => {
        this.$message.error('复制失败: ' + err);
      });
    },
    async submitTopic() {
      this.$refs.topicForm.validate(async (valid) => {
        if (valid) {
          try {
            // 获取当前用户ID（应该从登录信息中获取）
            const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
            const authorId = currentUser.id || 1
            
            const topicData = {
              title: this.newTopic.title,
              content: this.newTopic.content,
              groupId: this.groupInfo.id,
              authorId: authorId
            }
            
            const res = await topicApi.saveTopic(topicData)
            if (res.code === '200') {
              this.$message.success('话题发表成功！')
              this.showCreateTopicDialog = false
              // 重新加载话题列表
              this.loadTopics(this.groupInfo.id)
            } else {
              this.$message.error(res.msg || '发表话题失败')
            }
          } catch (err) {
            this.$message.error('发表话题失败: ' + err.message)
          }
        }
      })
    },
    async loadGroupInfo(groupId) {
      try {
        const res = await groupApi.getGroupById(groupId)
        if (res.code === '200') {
          this.groupInfo = {
            id: res.data.id,
            name: res.data.name,
            avatar: res.data.avatar || '',
            description: res.data.description,
            creatorId: res.data.creatorId,
            members: res.data.memberCount || 0,
            topics: res.data.topicCount || 0,
            createTime: res.data.createdAt ? new Date(res.data.createdAt).toLocaleDateString() : ''
          }
          // 解散权限:仅小组创建者或管理员(与后端校验一致)
          const u = JSON.parse(localStorage.getItem("user") || "{}")
          this.canDisband = (u.role === '管理员') || (res.data.creatorId != null && u.id === res.data.creatorId)
        } else {
          this.$message.error(res.msg || '获取小组信息失败')
          // 获取失败时跳转到社区首页
          this.$router.push('/community/home').catch(err => {
            if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
              console.error('路由跳转错误:', err);
            }
          });
        }
      } catch (err) {
        this.$message.error('获取小组信息失败: ' + err.message)
        // 获取失败时跳转到社区首页
        this.$router.push('/community/home').catch(err => {
          if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
            console.error('路由跳转错误:', err);
          }
        });
      }
    },
    async loadTopics(groupId) {
      try {
        // 使用新添加的API获取小组最新话题（带分页）
        const res = await groupApi.getLatestTopicsByPage(
          groupId, 
          this.topicPagination.pageNum, 
          this.topicPagination.pageSize
        )
        if (res.code === '200') {
          this.topics = res.data.records.map(topic => ({
            id: topic.id,
            title: topic.title,
            author: topic.authorName || '匿名用户',
            date: topic.createdAt ? new Date(topic.createdAt).toLocaleDateString() : '',
            likes: topic.likeCount || 0,
            replies: topic.commentCount || 0
          }))
          this.topicPagination.total = parseInt(res.data.total)
          this.topicPagination.pageNum = parseInt(res.data.current)
          this.topicPagination.pageSize = parseInt(res.data.size)
        } else {
          this.$message.error(res.msg || '获取话题列表失败')
        }
      } catch (err) {
        this.$message.error('获取话题列表失败: ' + err.message)
      }
    },
    async loadMembers(groupId) {
      try {
        // 使用分页API获取小组成员
        const res = await groupMemberApi.getGroupMembersByPage(
          this.memberPagination.pageNum,
          this.memberPagination.pageSize,
          groupId
        )
        if (res.code === '200') {
          // 这里需要将成员数据转换为前端需要的格式
          this.members = res.data.records.map(member => ({
            id: member.id,
            name: member.username || '匿名用户',
            avatar: member.avatar || '',
            role: member.role === 'admin' ? '管理员' : member.role === 'moderator' ? '版主' : '成员'
          }))
          this.memberPagination.total = parseInt(res.data.total)
          this.memberPagination.pageNum = parseInt(res.data.current)
          this.memberPagination.pageSize = parseInt(res.data.size)
          
          // 更新小组信息中的成员数量
          if (this.groupInfo) {
            this.groupInfo.members = parseInt(res.data.total);
          }
        } else {
          this.$message.error(res.msg || '获取成员列表失败')
        }
      } catch (err) {
        this.$message.error('获取成员列表失败: ' + err.message)
      }
    },
    goBack() {
      this.$router.push('/community/home').catch(err => {
        if (err.name !== 'NavigationDuplicated') {
          throw err;
        }
      });
    },
    joinGroup() {
      // 加入小组逻辑
      const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = currentUser.id;
      
      if (!userId) {
        this.$message.error('请先登录');
        return;
      }
      
      const groupMemberData = {
        groupId: this.groupInfo.id,
        userId: userId,
        role: 'member' // 默认为普通成员
      };
      
      groupMemberApi.saveGroupMember(groupMemberData).then(res => {
        if (res.code === '200') {
          this.isMember = true;
          this.userRole = 'member';
          this.$message.success('成功加入小组！');
          // 刷新整个页面数据
          this.refreshPageData();
        } else {
          this.$message.error(res.msg || '加入小组失败');
        }
      }).catch(err => {
        this.$message.error('加入小组失败: ' + err.message);
      });
    },
    leaveGroup() {
      // 退出小组逻辑
      const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = currentUser.id;
      
      if (!userId) {
        this.$message.error('请先登录');
        return;
      }
      
      groupMemberApi.removeMemberFromGroup(userId, this.groupInfo.id).then(res => {
        if (res.code === '200') {
          this.isMember = false;
          this.userRole = '';
          this.$message.info('已退出小组');
          // 刷新整个页面数据
          this.refreshPageData();
        } else {
          this.$message.error(res.msg || '退出小组失败');
        }
      }).catch(err => {
        this.$message.error('退出小组失败: ' + err.message);
      });
    },
    disbandGroup() {
      // 解散小组逻辑
      const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = currentUser.id;
      
      if (!userId) {
        this.$message.error('请先登录');
        return;
      }
      
      this.$confirm('此操作将永久删除该小组及其所有相关数据（成员、话题、评论、点赞等）, 是否继续?', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(async () => {
        try {
          const res = await groupApi.deleteGroupCompletely(this.groupInfo.id);
          if (res.code === '200') {
            this.$message.success('小组已成功解散');
            // 跳转到社区主页
            this.$router.push('/community/home').catch(err => {
              if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
                console.error('路由跳转错误:', err);
              }
            });
          } else {
            this.$message.error(res.msg || '解散小组失败');
          }
        } catch (err) {
          this.$message.error('解散小组失败: ' + err.message);
        }
      }).catch(() => {
        this.$message.info('已取消操作');
      });
    },
    viewTopic(id) {
      this.$router.push(`/community/topic/${id}`).catch(err => {
        if (err.name !== 'NavigationDuplicated') {
          throw err;
        }
      });
    },
    handleTopicSizeChange(pageSize) {
      this.topicPagination.pageSize = parseInt(pageSize);
      this.topicPagination.pageNum = 1;
      this.loadTopics(this.groupInfo.id);
    },
    handleTopicCurrentChange(pageNum) {
      this.topicPagination.pageNum = parseInt(pageNum);
      this.loadTopics(this.groupInfo.id);
    },
    handleMemberSizeChange(pageSize) {
      this.memberPagination.pageSize = parseInt(pageSize);
      this.memberPagination.pageNum = 1;
      this.loadMembers(this.groupInfo.id);
    },
    handleMemberCurrentChange(pageNum) {
      this.memberPagination.pageNum = parseInt(pageNum);
      this.loadMembers(this.groupInfo.id)
    },
    async checkIsMember(groupId) {
      try {
        // 获取当前用户ID
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}")
        const userId = currentUser.id
        
        if (!userId) {
          this.isMember = false
          this.userRole = ''
          return
        }
        
        // 检查用户是否为小组成员及角色
        const res = await groupMemberApi.getUserMembershipInfo(userId, groupId)
        if (res.code === '200') {
          this.isMember = res.data.isMember
          this.userRole = res.data.role
        }
      } catch (err) {
        console.error('检查成员身份失败:', err)
        this.isMember = false
        this.userRole = ''
      }
    },
    async refreshPageData() {
      const groupId = this.groupInfo.id;
      if (groupId) {
        // 重置分页到第一页
        this.memberPagination.pageNum = 1;
        this.topicPagination.pageNum = 1;
        // 重新加载所有数据
        await this.loadGroupInfo(groupId);
        await this.loadTopics(groupId);
        await this.loadMembers(groupId);
        await this.checkIsMember(groupId);
      }
    },
  }
}
</script>

<style scoped>
.group-detail-container {
  padding: 20px;
}

.group-header {
  margin: 20px 0;
}

.group-info {
  display: flex;
  align-items: center;
  gap: 20px;
}

.group-avatar {
  width: 80px;
  height: 80px;
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

.group-details h2 {
  color: #2c3e50;
  margin-bottom: 10px;
}

.group-details p {
  color: #7f8c8d;
  margin-bottom: 15px;
}

.group-stats {
  display: flex;
  gap: 20px;
  margin-top: 10px;
  color: #7f8c8d;
}

.group-actions {
  display: flex;
  gap: 10px;
}

.topic-card {
  margin-bottom: 15px;
  cursor: pointer;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  transition: box-shadow 0.3s ease;
}

.topic-card:hover {
  box-shadow: 0 4px 12px rgba(74, 144, 226, 0.15);
}

.topic-card h3 {
  color: #2c3e50;
  margin-bottom: 10px;
}

.topic-card p {
  color: #7f8c8d;
  margin-bottom: 15px;
  font-size: 14px;
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

.member-card {
  margin-bottom: 15px;
  border: 1px solid #eaeaea;
  border-radius: 8px;
}

.loading-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 200px;
}

.member-info {
  display: flex;
  align-items: center;
  gap: 15px;
}

.member-avatar {
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f5f7fa;
  border-radius: 50%;
}

.member-avatar-img {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  object-fit: cover;
}

.member-details h4 {
  color: #2c3e50;
  margin-bottom: 5px;
}

.member-details p {
  color: #7f8c8d;
  margin: 0;
  font-size: 13px;
}

.el-tabs__item.is-active {
  color: #4a90e2 !important;
}

.el-tabs__item:hover {
  color: #4a90e2;
}

.el-tabs__active-bar {
  background-color: #4a90e2;
}

.el-page-header {
  margin-bottom: 20px;
}

.el-page-header__content {
  color: #2c3e50;
  font-weight: bold;
}

.el-card {
  border: 1px solid #eaeaea;
  border-radius: 8px;
}

.el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
}

.el-button--danger {
  background-color: #e74c3c;
  border-color: #e74c3c;
}

.el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
}

.dialog-footer .el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
}
</style>