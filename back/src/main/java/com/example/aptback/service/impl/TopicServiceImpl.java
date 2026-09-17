package com.example.aptback.service.impl;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.entity.Topic;
import com.example.aptback.mapper.TopicMapper;
import com.example.aptback.mapper.CommentMapper;
import com.example.aptback.mapper.LikeMapper;
import com.example.aptback.service.ITopicService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class TopicServiceImpl implements ITopicService {
    @Autowired
    private TopicMapper topicMapper;
    
    @Autowired
    private CommentMapper commentMapper;
    
    @Autowired
    private LikeMapper likeMapper;

    @Override
    public List<Topic> selectAll() {
        return topicMapper.selectList(null);
    }

    @Override
    public Topic selectById(Integer id) {
        return topicMapper.selectById(id);
    }

    @Override
    public IPage<Topic> selectPage(Integer pageNum, Integer pageSize, Integer groupId, String title) {
        Page<Topic> page = new Page<>(pageNum, pageSize);
        LambdaQueryWrapper<Topic> queryWrapper = new LambdaQueryWrapper<>();
        if (groupId != null) {
            queryWrapper.eq(Topic::getGroupId, groupId);
        }
        if (StrUtil.isNotBlank(title)) {
            queryWrapper.like(Topic::getTitle, title.trim());
        }
        queryWrapper.orderByDesc(Topic::getId);
        return topicMapper.selectPage(page, queryWrapper);
    }

    @Override
    public void insert(Topic topic) {
        if (topic.getTitle() == null || topic.getTitle().isEmpty()) {
            throw new RuntimeException("话题标题不能为空");
        }
        
        if (topic.getContent() == null || topic.getContent().isEmpty()) {
            throw new RuntimeException("话题内容不能为空");
        }
        
        // 如果没有设置小组ID，则抛出异常
        if (topic.getGroupId() == null) {
            throw new RuntimeException("小组ID不能为空");
        }
        
        // 如果没有设置作者ID，则抛出异常
        if (topic.getAuthorId() == null) {
            throw new RuntimeException("作者ID不能为空");
        }
        
        topic.setCreatedAt(new Date());
        topic.setUpdatedAt(new Date());
        topicMapper.insert(topic);
    }

    @Override
    public void update(Topic topic) {
        if (topic.getTitle() == null || topic.getTitle().isEmpty()) {
            throw new RuntimeException("话题标题不能为空");
        }
        
        if (topic.getContent() == null || topic.getContent().isEmpty()) {
            throw new RuntimeException("话题内容不能为空");
        }
        
        topic.setUpdatedAt(new Date());
        topicMapper.updateById(topic);
    }

    @Override
    public void delete(Integer id) {
        // 先删除相关的点赞记录
        LambdaQueryWrapper<com.example.aptback.entity.Like> likeQueryWrapper = new LambdaQueryWrapper<>();
        likeQueryWrapper.eq(com.example.aptback.entity.Like::getTopicId, id);
        likeMapper.delete(likeQueryWrapper);
        
        // 再删除相关的评论记录
        LambdaQueryWrapper<com.example.aptback.entity.Comment> commentQueryWrapper = new LambdaQueryWrapper<>();
        commentQueryWrapper.eq(com.example.aptback.entity.Comment::getTopicId, id);
        commentMapper.delete(commentQueryWrapper);
        
        // 最后删除话题本身
        topicMapper.deleteById(id);
    }
    
    @Override
    public List<Topic> selectByGroupId(Integer groupId) {
        LambdaQueryWrapper<Topic> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Topic::getGroupId, groupId);
        queryWrapper.orderByDesc(Topic::getId);
        return topicMapper.selectList(queryWrapper);
    }
    
    @Override
    public List<Topic> selectByAuthorId(Integer authorId) {
        LambdaQueryWrapper<Topic> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Topic::getAuthorId, authorId);
        queryWrapper.orderByDesc(Topic::getId);
        return topicMapper.selectList(queryWrapper);
    }
    
    @Override
    public List<Topic> selectLatestByGroupId(Integer groupId, Integer size) {
        LambdaQueryWrapper<Topic> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Topic::getGroupId, groupId);
        queryWrapper.orderByDesc(Topic::getCreatedAt);
        Page<Topic> page = new Page<>(1, size);
        IPage<Topic> result = topicMapper.selectPage(page, queryWrapper);
        return result.getRecords();
    }
    
    @Override
    public List<Topic> selectTopTopics(Integer size) {
        LambdaQueryWrapper<Topic> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.orderByDesc(Topic::getCreatedAt);
        Page<Topic> page = new Page<>(1, size);
        IPage<Topic> result = topicMapper.selectPage(page, queryWrapper);
        return result.getRecords();
    }
}