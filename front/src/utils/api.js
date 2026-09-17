import request from '@/utils/request'

// 用户相关接口
export const userApi = {
  // 用户登录
  login: (data) => request.post('/login', data),
  
  // 用户注册
  register: (data) => request.post('/register', data),
  
  // 获取用户信息
  getUserInfo: () => request.get('/user/getUserInfo'),
  
  // 根据ID获取用户信息
  getUserInfoById: (id) => request.get('/user/selectById', { params: { id } }),
  
  // 更新用户信息
  updateUserInfo: (data) => request.post('/user/updateUserInfo', data)
}

// 小组相关接口
export const groupApi = {
  // 获取所有小组
  getAllGroups: () => request.get('/group/selectAll'),
  
  // 根据ID获取小组
  getGroupById: (id) => request.get('/group/selectById', { params: { id } }),
  
  // 分页获取小组列表
  getGroupsByPage: (pageNum, pageSize, name) => request.get('/group/selectPage', {
    params: { pageNum, pageSize, name }
  }),
  
  // 获取最新成立的小组
  getLatestGroups: () => request.get('/group/latest'),
  
  // 获取指定小组的最新话题（带分页）
  getLatestTopicsByPage: (id, pageNum, pageSize) => request.get('/group/latestTopics', {
    params: { id, pageNum, pageSize }
  }),
  
  // 创建或更新小组
  saveGroup: (data) => request.post('/group', data),
  
  // 删除小组
  deleteGroup: (id) => request.delete('/group/delete', { params: { id } }),
  
  // 彻底删除小组及其所有相关数据
  deleteGroupCompletely: (id) => request.delete('/group/deleteCompletely', { params: { id } })
}

// 小组成员相关接口
export const groupMemberApi = {
  // 获取小组所有成员
  getMembersByGroupId: (groupId) => request.get('/group-member/selectByGroupId', { params: { groupId } }),
  
  // 获取用户参与的所有小组
  getGroupsByUserId: (userId) => request.get('/group-member/selectByUserId', { params: { userId } }),
  
  // 分页获取小组成员列表（带用户信息）
  getGroupMembersByPage: (pageNum, pageSize, groupId) => request.get('/group-member/selectPage', {
    params: { pageNum, pageSize, groupId }
  }),
  
  // 加入小组
  saveGroupMember: (data) => request.post('/group-member', data),
  
  // 退出小组
  removeMemberFromGroup: (userId, groupId) => request.delete('/group-member/removeMember', {
    params: { userId, groupId }
  }),
  
  // 检查用户是否为小组成员及角色信息
  getUserMembershipInfo: (userId, groupId) => request.get('/group-member/membershipInfo', {
    params: { userId, groupId }
  })
}

// 话题相关接口
export const topicApi = {
  // 获取所有话题
  getAllTopics: () => request.get('/topic/selectAll'),
  
  // 根据ID获取话题
  getTopicById: (id) => request.get('/topic/selectById', { params: { id } }),
  
  // 根据小组ID获取话题列表
  getTopicsByGroupId: (groupId) => request.get('/topic/selectByGroupId', { params: { groupId } }),
  
  // 根据作者ID获取话题列表
  getTopicsByAuthorId: (authorId) => request.get('/topic/selectByAuthorId', { params: { authorId } }),
  
  // 分页获取话题列表
  getTopicsByPage: (pageNum, pageSize, groupId, title) => request.get('/topic/selectPage', {
    params: { pageNum, pageSize, groupId, title }
  }),
  
  // 获取热门话题
  getTopTopics: () => request.get('/topic/top'),
  
  // 创建或更新话题
  saveTopic: (data) => request.post('/topic', data),
  
  // 删除话题
  deleteTopic: (id) => request.delete('/topic/delete', { params: { id } })
}

// 评论相关接口
export const commentApi = {
  // 根据话题ID获取评论列表
  getCommentsByTopicId: (topicId) => request.get('/comment/selectByTopicId', { params: { topicId } }),
  
  // 创建或更新评论
  saveComment: (data) => request.post('/comment', data),
  
  // 删除评论
  deleteComment: (id) => request.delete('/comment/delete', { params: { id } })
}

// 点赞相关接口
export const likeApi = {
  // 检查是否点赞
  isLiked: (userId, topicId) => request.get('/like/isLiked', { params: { userId, topicId } }),
  
  // 获取点赞数
  getLikeCount: (topicId) => request.get('/like/count', { params: { topicId } }),
  
  // 点赞或取消点赞
  toggleLike: (userId, topicId) => request.post('/like/toggle', { userId, topicId })
}