package com.example.aptback.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.entity.Comment;
import com.example.aptback.mapper.CommentMapper;
import com.example.aptback.service.ICommentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class CommentServiceImpl implements ICommentService {
    @Autowired
    private CommentMapper commentMapper;

    @Override
    public List<Comment> selectAll() {
        return commentMapper.selectList(null);
    }

    @Override
    public Comment selectById(Integer id) {
        return commentMapper.selectById(id);
    }

    @Override
    public IPage<Comment> selectPage(Integer pageNum, Integer pageSize, Integer topicId) {
        Page<Comment> page = new Page<>(pageNum, pageSize);
        LambdaQueryWrapper<Comment> queryWrapper = new LambdaQueryWrapper<>();
        if (topicId != null) {
            queryWrapper.eq(Comment::getTopicId, topicId);
        }
        queryWrapper.orderByAsc(Comment::getId);
        return commentMapper.selectPage(page, queryWrapper);
    }

    @Override
    public void insert(Comment comment) {
        if (comment.getContent() == null || comment.getContent().isEmpty()) {
            throw new RuntimeException("评论内容不能为空");
        }
        
        comment.setCreatedAt(new Date());
        comment.setUpdatedAt(new Date());
        commentMapper.insert(comment);
    }

    @Override
    public void update(Comment comment) {
        if (comment.getContent() == null || comment.getContent().isEmpty()) {
            throw new RuntimeException("评论内容不能为空");
        }
        
        comment.setUpdatedAt(new Date());
        commentMapper.updateById(comment);
    }

    @Override
    public void delete(Integer id) {
        // 删除评论及其所有回复
        LambdaQueryWrapper<Comment> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Comment::getParentId, id);
        commentMapper.delete(queryWrapper);
        
        commentMapper.deleteById(id);
    }
    
    @Override
    public List<Comment> selectByTopicId(Integer topicId) {
        LambdaQueryWrapper<Comment> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Comment::getTopicId, topicId);
        // 移除parentId为null的限制，返回所有评论
        queryWrapper.orderByAsc(Comment::getId);
        return commentMapper.selectList(queryWrapper);
    }
    
    @Override
    public List<Comment> selectByAuthorId(Integer authorId) {
        LambdaQueryWrapper<Comment> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Comment::getAuthorId, authorId);
        queryWrapper.orderByDesc(Comment::getId);
        return commentMapper.selectList(queryWrapper);
    }
    
    @Override
    public List<Comment> selectReplies(Integer parentId) {
        LambdaQueryWrapper<Comment> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Comment::getParentId, parentId);
        queryWrapper.orderByAsc(Comment::getId);
        return commentMapper.selectList(queryWrapper);
    }
}