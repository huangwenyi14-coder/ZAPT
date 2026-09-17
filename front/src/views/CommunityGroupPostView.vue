<template>
  <div class="post-detail-container">
    <el-page-header @back="goBack" content="话题详情">
    </el-page-header>

    <!-- 话题内容 -->
    <div class="post-header">
      <el-card>
        <div class="post-title-row">
          <h1>{{ post.title }}</h1>
          <div class="author-avatar-container">
            <img v-if="post.authorAvatar && post.authorAvatar.startsWith('http')" :src="post.authorAvatar" class="author-avatar" alt="作者头像" />
            <div v-else class="author-avatar author-avatar-default">👤</div>
          </div>
        </div>
        <div class="post-meta">
          <span class="meta-item">作者：{{ post.author }}</span>
          <span class="meta-item">发布日期：{{ post.date }}</span>
        </div>
        <div class="post-content" v-html="post.content"></div>
        <div class="post-actions">
          <el-button :type="liked ? 'primary' : ''" @click="toggleLike">
            <i class="el-icon-thumb"></i>
            {{ liked ? '已赞' : '点赞' }} ({{ likeCount }})
          </el-button>
          <el-button @click="sharePost">
            <i class="el-icon-share"></i>
            分享
          </el-button>
        </div>
      </el-card>
    </div>

    <!-- 评论区 -->
    <div class="comments-section">
      <h2>评论 ({{ comments.length }})</h2>
      
      <!-- 评论列表 -->
      <div class="comments-list">
        <el-card v-for="comment in comments" :key="comment.id" class="comment-card">
          <div class="comment-header">
            <div class="user-info">
              <img v-if="comment.avatar && comment.avatar.startsWith('http')" :src="comment.avatar" class="user-avatar" />
              <div v-else class="avatar-placeholder">👤</div>
              <span class="comment-author">{{ comment.author }}</span>
            </div>
            <span class="comment-date">{{ comment.date }}</span>
          </div>
          <div class="comment-content" v-html="comment.content"></div>
          <div class="comment-actions">
            <el-button type="text" @click="replyTo(comment)">回复</el-button>
          </div>
          
          <!-- 回复编辑器 -->
          <div v-if="replyingTo === comment.id" class="reply-editor">
            <quill-editor
              v-model="replyComment.content"
              :options="editorOption"
              class="reply-quill-editor">
            </quill-editor>
            <div class="reply-actions">
              <el-button type="primary" @click="submitReply(comment.id)" size="small">发表回复</el-button>
              <el-button @click="cancelReply" size="small">取消</el-button>
            </div>
          </div>
          
          <!-- 回复列表 -->
          <div class="replies-list" v-if="comment.replies && comment.replies.length > 0">
            <div v-for="reply in comment.replies" :key="reply.id" class="reply-item">
              <div class="reply-header">
                <div class="user-info">
                  <img v-if="reply.avatar && reply.avatar.startsWith('http')" :src="reply.avatar" class="user-avatar small" />
                  <div v-else class="avatar-placeholder small">👤</div>
                  <span class="reply-author">{{ reply.author }}</span>
                </div>
                <span class="reply-date">{{ reply.date }}</span>
              </div>
              <div class="reply-to" v-if="reply.parentAuthor">
                @{{ reply.parentAuthor }}
              </div>
              <div class="reply-content" v-html="reply.content"></div>
            </div>
          </div>
        </el-card>
      </div>

      <!-- 发表评论 -->
      <div class="comment-form">
        <h3>发表评论</h3>
        <quill-editor
          v-model="newComment.content"
          :options="editorOption"
          class="comment-quill-editor">
        </quill-editor>
        <div class="form-actions">
          <el-button type="primary" @click="submitComment">发表评论</el-button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { topicApi, commentApi, likeApi, userApi } from '@/utils/api'
import { quillEditor } from 'vue-quill-editor'
import 'quill/dist/quill.core.css'
import 'quill/dist/quill.snow.css'
import 'quill/dist/quill.bubble.css'

export default {
  name: 'CommunityGroupPostView',
  components: {
    quillEditor
  },
  data() {
    return {
      liked: false,
      likeCount: 0,
      replyingTo: null, // 当前正在回复的评论ID
      replyComment: {
        content: ''
      },
      post: {
        id: 0,
        title: '',
        author: '',
        authorAvatar: '',
        date: '',
        views: 0,
        content: ''
      },
      comments: [],
      newComment: {
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
        placeholder: '请输入评论内容...'
      }
    }
  },
  created() {
    const topicId = this.$route.params.id
    if (topicId) {
      this.loadTopic(topicId)
      this.loadComments(topicId)
      this.checkIfLiked(topicId)
      this.loadLikeCount(topicId)
    }
  },
  methods: {
    async loadTopic(topicId) {
      try {
        const res = await topicApi.getTopicById(topicId)
        if (res.code === '200') {
          // 获取作者信息
          let authorAvatar = ''
          if (res.data.authorId) {
            try {
              const authorRes = await userApi.getUserInfoById(res.data.authorId)
              if (authorRes.code === '200') {
                authorAvatar = authorRes.data.avatar || ''
              }
            } catch (err) {
              console.error('获取作者信息失败:', err)
            }
          }
          
          this.post = {
            id: res.data.id,
            title: res.data.title,
            author: res.data.authorName || '匿名用户',
            authorAvatar: authorAvatar,
            date: res.data.createdAt ? new Date(res.data.createdAt).toLocaleString('zh-CN', {
              year: 'numeric',
              month: '2-digit',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit'
            }) : '',
            content: res.data.content
          }
        } else {
          this.$message.error(res.msg || '获取话题详情失败')
        }
      } catch (err) {
        this.$message.error('获取话题详情失败: ' + err.message)
      }
    },
    async loadComments(topicId) {
      try {
        const res = await commentApi.getCommentsByTopicId(topicId)
        if (res.code === '200') {
          // 构造评论树结构
          const allComments = res.data
          
          // 获取所有涉及的用户ID
          const userIds = [...new Set(allComments.map(c => c.authorId))]
          
          // 批量获取用户信息
          const userPromises = userIds.map(id => userApi.getUserInfoById(id))
          const userResults = await Promise.all(userPromises)
          const userMap = {}
          userResults.forEach((result, index) => {
            if (result.code === '200') {
              userMap[userIds[index]] = result.data
            }
          })
          
          // 构建评论树
          const commentTree = []
          const commentMap = {}
          
          // 初始化所有评论
          allComments.forEach(comment => {
            const author = userMap[comment.authorId] || { userName: '匿名用户', avatar: '' }
            commentMap[comment.id] = {
              id: comment.id,
              author: author.userName || '匿名用户',
              avatar: author.avatar || '',
              date: comment.createdAt ? new Date(comment.createdAt).toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
              }) : '',
              content: comment.content,
              replies: [],
              parentId: comment.parentId
            }
          })
          
          // 构建父子关系
          allComments.forEach(comment => {
            if (!comment.parentId) {
              // 顶级评论
              commentTree.push(commentMap[comment.id])
            } else {
              // 回复评论
              if (commentMap[comment.parentId]) {
                commentMap[comment.parentId].replies.push(commentMap[comment.id])
              }
            }
          })
          
          this.comments = commentTree
        } else {
          this.$message.error(res.msg || '获取评论列表失败')
        }
      } catch (err) {
        this.$message.error('获取评论列表失败: ' + err.message)
      }
    },
    async checkIfLiked(topicId) {
      try {
        // 从localStorage获取当前用户信息
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
        const userId = currentUser.id || 1;
        
        const res = await likeApi.isLiked(userId, topicId);
        if (res.code === '200') {
          this.liked = res.data;
        }
      } catch (err) {
        console.error('检查点赞状态失败: ' + err.message);
      }
    },
    async loadLikeCount(topicId) {
      try {
        const res = await likeApi.getLikeCount(topicId)
        if (res.code === '200') {
          this.likeCount = res.data
        }
      } catch (err) {
        console.error('获取点赞数失败: ' + err.message)
      }
    },
    goBack() {
      this.$router.go(-1);
    },
    async toggleLike() {
      try {
        // 从localStorage获取当前用户信息
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
        const userId = currentUser.id || 1;
        
        const res = await likeApi.toggleLike(userId, this.post.id);
        if (res.code === '200') {
          this.liked = !this.liked;
          // 更新点赞数
          if (this.liked) {
            this.likeCount++;
          } else {
            this.likeCount = Math.max(0, this.likeCount - 1);
          }
          this.$message.success(this.liked ? '点赞成功！' : '已取消点赞');
        } else {
          this.$message.error(res.msg || (this.liked ? '点赞失败' : '取消点赞失败'));
        }
      } catch (err) {
        this.$message.error((this.liked ? '点赞' : '取消点赞') + '失败: ' + err.message);
      }
    },
    sharePost() {
      const url = window.location.href;
      navigator.clipboard.writeText(url).then(() => {
        this.$message.success('链接已复制到剪贴板');
      }).catch(err => {
        this.$message.error('复制失败: ' + err);
      });
    },
    replyTo(comment) {
      this.replyingTo = comment.id;
      this.replyComment.content = '';
    },
    cancelReply() {
      this.replyingTo = null;
      this.replyComment.content = '';
    },
    async submitReply(parentId) {
      if (!this.replyComment.content.trim()) {
        this.$message.warning('请输入回复内容');
        return;
      }
      
      try {
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
        const authorId = currentUser.id;
        const res = await commentApi.saveComment({
          topicId: this.post.id,
          authorId: authorId, // 应该从当前用户信息中获取
          content: this.replyComment.content,
          parentId: parentId
        })
        
        if (res.code === '200') {
          this.$message.success('回复发表成功！');
          this.cancelReply();
          // 重新加载评论列表
          this.loadComments(this.post.id)
        } else {
          this.$message.error(res.msg || '发表回复失败')
        }
      } catch (err) {
        this.$message.error('发表回复失败: ' + err.message)
      }
    },
    async submitComment() {
      if (!this.newComment.content.trim()) {
        this.$message.warning('请输入评论内容');
        return;
      }
      
      try {
        // 从localStorage获取当前用户信息
        const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
        const authorId = currentUser.id;
        
        const res = await commentApi.saveComment({
          topicId: this.post.id,
          authorId: authorId,
          content: this.newComment.content,
          parentId: null // 顶级评论
        })
        
        if (res.code === '200') {
          this.$message.success('评论发表成功！');
          this.newComment.content = '';
          // 重新加载评论列表
          this.loadComments(this.post.id)
        } else {
          this.$message.error(res.msg || '发表评论失败')
        }
      } catch (err) {
        this.$message.error('发表评论失败: ' + err.message)
      }
    }
  }
}
</script>

<style scoped>
.post-detail-container {
  padding: 20px;
}

.post-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.author-avatar-container {
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f5f7fa;
  border-radius: 50%;
}

.author-avatar {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  object-fit: cover;
  border: 2px solid #4a90e2;
}

.author-avatar-default {
  font-size: 1.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
  background-color: #f0f2f5;
}

.post-header h1 {
  color: #2c3e50;
  margin: 0;
  flex-grow: 1;
  margin-right: 15px;
}

.post-meta {
  color: #7f8c8d;
  margin: 10px 0;
  font-size: 14px;
  padding: 10px 15px;
  background-color: #e3f2fd;
  border-radius: 5px;
  display: inline-block;
}

.meta-item {
  margin-right: 20px;
}

.post-content {
  margin: 20px 0;
  line-height: 1.6;
  color: #2c3e50;
}

.post-actions {
  margin-top: 20px;
  text-align: right;
  padding-top: 20px;
  border-top: 1px solid #eee;
}

.el-button {
  margin-left: 10px;
}

.el-button--primary {
  background-color: #4a90e2;
  border-color: #4a90e2;
}

.comments-section {
  margin-top: 30px;
}

.comments-section h2 {
  color: #2c3e50;
  border-bottom: 2px solid #4a90e2;
  padding-bottom: 10px;
  margin-bottom: 20px;
}

.comment-card {
  margin-bottom: 15px;
  border: 1px solid #eaeaea;
  border-radius: 8px;
}

.comment-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
  padding-bottom: 10px;
  border-bottom: 1px solid #eee;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.user-avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  object-fit: cover;
}

.user-avatar.small {
  width: 24px;
  height: 24px;
}

.avatar-placeholder {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background-color: #f0f2f5;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
}

.avatar-placeholder.small {
  width: 24px;
  height: 24px;
  font-size: 12px;
}

.comment-author {
  font-weight: bold;
  color: #2c3e50;
}

.comment-date {
  color: #7f8c8d;
  font-size: 13px;
}

.comment-content {
  color: #2c3e50;
  line-height: 1.5;
  margin-bottom: 10px;
}

.reply-editor {
  margin-top: 15px;
  padding: 10px;
  border: 1px solid #eaeaea;
  border-radius: 4px;
  background-color: #fafafa;
}

.reply-item {
  margin-top: 15px;
  padding-left: 20px;
  border-left: 2px solid #4a90e2;
}

.reply-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 5px;
}

.reply-author {
  font-weight: bold;
  font-size: 0.9em;
  color: #2c3e50;
}

.reply-date {
  color: #7f8c8d;
  font-size: 0.9em;
}

.reply-to {
  color: #4a90e2;
  font-size: 0.9em;
  margin-bottom: 5px;
}

.reply-content {
  color: #2c3e50;
  line-height: 1.5;
}

.comment-form {
  margin-top: 30px;
  padding: 20px;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  background-color: #fafafa;
}

.comment-form h3 {
  color: #2c3e50;
  margin-bottom: 15px;
}

.form-actions, .reply-actions {
  margin-top: 15px;
  text-align: right;
}

.reply-actions .el-button {
  margin-left: 10px;
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
</style>