package com.example.aptback.service.impl;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.entity.UserGroup;
import com.example.aptback.mapper.UserGroupMapper;
import com.example.aptback.service.IUserGroupService;
import com.example.aptback.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.aptback.mapper.GroupMemberMapper;
import com.example.aptback.mapper.TopicMapper;
import com.example.aptback.mapper.LikeMapper;
import com.example.aptback.mapper.CommentMapper;

import java.util.Date;
import java.util.List;

@Service
public class UserGroupServiceImpl implements IUserGroupService {
    @Autowired
    private UserGroupMapper userGroupMapper;
    
    @Autowired
    private GroupMemberMapper groupMemberMapper;
    
    @Autowired
    private TopicMapper topicMapper;
    
    @Autowired
    private LikeMapper likeMapper;
    
    @Autowired
    private CommentMapper commentMapper;
    
    @Autowired
    private IUserService userService;

    @Override
    public List<UserGroup> selectAll() {
        return userGroupMapper.selectList(null);
    }

    @Override
    public UserGroup selectById(Integer id) {
        return userGroupMapper.selectById(id);
    }

    @Override
    public IPage<UserGroup> selectPage(Integer pageNum, Integer pageSize, String name) {
        Page<UserGroup> page = new Page<>(pageNum, pageSize);
        LambdaQueryWrapper<UserGroup> queryWrapper = new LambdaQueryWrapper<>();
        if (StrUtil.isNotBlank(name)) {
            queryWrapper.like(UserGroup::getName, name.trim());
        }
        return userGroupMapper.selectPage(page, queryWrapper);
    }

    @Override
    public void insert(UserGroup userGroup) {
        if (userGroup.getName() == null || userGroup.getName().isEmpty()) {
            throw new RuntimeException("小组名称不能为空");
        }

        // 唯一性校验
        LambdaQueryWrapper<UserGroup> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(UserGroup::getName, userGroup.getName());
        UserGroup existingGroup = userGroupMapper.selectOne(queryWrapper);
        if (existingGroup != null) {
            throw new RuntimeException("小组名称已存在");
        }

        userGroup.setCreatedAt(new Date());
        userGroup.setUpdatedAt(new Date());
        userGroupMapper.insert(userGroup);
        
        // 创建者自动成为小组管理员
        if (userGroup.getCreatorId() != null) {
            com.example.aptback.entity.GroupMember groupMember = new com.example.aptback.entity.GroupMember();
            groupMember.setGroupId(userGroup.getId());
            groupMember.setUserId(userGroup.getCreatorId());
            groupMember.setRole("moderator"); // 创建者为管理员
            groupMember.setCreatedAt(new Date());
            groupMember.setUpdatedAt(new Date());
            groupMemberMapper.insert(groupMember);
        }
    }

    @Override
    public void update(UserGroup userGroup) {
        if (userGroup.getName() == null || userGroup.getName().isEmpty()) {
            throw new RuntimeException("小组名称不能为空");
        }

        userGroup.setUpdatedAt(new Date());
        userGroupMapper.updateById(userGroup);
    }

    @Override
    public void delete(Integer id) {
        userGroupMapper.deleteById(id);
    }
    
    @Override
    public void deleteGroupAndRelatedData(Integer groupId) {
        // 1. 查找该小组下的所有话题
        LambdaQueryWrapper<com.example.aptback.entity.Topic> topicQueryWrapper = new LambdaQueryWrapper<>();
        topicQueryWrapper.eq(com.example.aptback.entity.Topic::getGroupId, groupId);
        List<com.example.aptback.entity.Topic> topics = topicMapper.selectList(topicQueryWrapper);
        
        // 2. 删除每个话题相关的点赞和评论
        for (com.example.aptback.entity.Topic topic : topics) {
            // 删除话题相关的点赞
            LambdaQueryWrapper<com.example.aptback.entity.Like> likeQueryWrapper = new LambdaQueryWrapper<>();
            likeQueryWrapper.eq(com.example.aptback.entity.Like::getTopicId, topic.getId());
            likeMapper.delete(likeQueryWrapper);
            
            // 删除话题相关的评论
            LambdaQueryWrapper<com.example.aptback.entity.Comment> commentQueryWrapper = new LambdaQueryWrapper<>();
            commentQueryWrapper.eq(com.example.aptback.entity.Comment::getTopicId, topic.getId());
            commentMapper.delete(commentQueryWrapper);
        }
        
        // 3. 删除该小组下的所有话题
        topicMapper.delete(topicQueryWrapper);
        
        // 4. 删除该小组的所有成员
        LambdaQueryWrapper<com.example.aptback.entity.GroupMember> memberQueryWrapper = new LambdaQueryWrapper<>();
        memberQueryWrapper.eq(com.example.aptback.entity.GroupMember::getGroupId, groupId);
        groupMemberMapper.delete(memberQueryWrapper);
        
        // 5. 最后删除小组本身
        userGroupMapper.deleteById(groupId);
    }
    
    @Override
    public List<UserGroup> selectLatestGroups(Integer size) {
        LambdaQueryWrapper<UserGroup> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.orderByDesc(UserGroup::getCreatedAt);
        Page<UserGroup> page = new Page<>(1, size);
        IPage<UserGroup> result = userGroupMapper.selectPage(page, queryWrapper);
        return result.getRecords();
    }
    
    @Override
    public String getGroupNameById(Integer id) {
        UserGroup group = userGroupMapper.selectById(id);
        return group != null ? group.getName() : "未知小组";
    }
    
    @Override
    public int getMemberCount(Integer groupId) {
        LambdaQueryWrapper<com.example.aptback.entity.GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(com.example.aptback.entity.GroupMember::getGroupId, groupId);
        return groupMemberMapper.selectCount(queryWrapper).intValue();
    }
    
    @Override
    public int getTopicCount(Integer groupId) {
        LambdaQueryWrapper<com.example.aptback.entity.Topic> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(com.example.aptback.entity.Topic::getGroupId, groupId);
        return topicMapper.selectCount(queryWrapper).intValue();
    }
}