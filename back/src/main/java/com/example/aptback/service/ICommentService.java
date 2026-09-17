package com.example.aptback.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.entity.Comment;

import java.util.List;

public interface ICommentService {
    List<Comment> selectAll();

    Comment selectById(Integer id);

    IPage<Comment> selectPage(Integer pageNum, Integer pageSize, Integer topicId);

    void insert(Comment comment);

    void update(Comment comment);

    void delete(Integer id);
    
    List<Comment> selectByTopicId(Integer topicId);
    
    List<Comment> selectByAuthorId(Integer authorId);
    
    List<Comment> selectReplies(Integer parentId);
}