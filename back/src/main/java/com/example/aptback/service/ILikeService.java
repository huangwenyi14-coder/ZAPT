package com.example.aptback.service;

import com.example.aptback.entity.Like;

import java.util.List;

public interface ILikeService {
    List<Like> selectAll();

    Like selectById(Integer id);

    void insert(Like like);

    void delete(Integer id);
    
    void toggleLike(Integer userId, Integer topicId);
    
    boolean isLiked(Integer userId, Integer topicId);
    
    int countByTopicId(Integer topicId);
}