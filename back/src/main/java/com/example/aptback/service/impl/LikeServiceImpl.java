package com.example.aptback.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.aptback.entity.Like;
import com.example.aptback.mapper.LikeMapper;
import com.example.aptback.service.ILikeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LikeServiceImpl implements ILikeService {
    @Autowired
    private LikeMapper likeMapper;

    @Override
    public List<Like> selectAll() {
        return likeMapper.selectList(null);
    }

    @Override
    public Like selectById(Integer id) {
        return likeMapper.selectById(id);
    }

    @Override
    public void insert(Like like) {
        // 检查是否已存在该用户的点赞记录
        LambdaQueryWrapper<Like> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Like::getUserId, like.getUserId());
        queryWrapper.eq(Like::getTopicId, like.getTopicId());
        Like existingLike = likeMapper.selectOne(queryWrapper);
        
        if (existingLike != null) {
            throw new RuntimeException("已点赞");
        }
        
        likeMapper.insert(like);
    }

    @Override
    public void delete(Integer id) {
        likeMapper.deleteById(id);
    }
    
    @Override
    public void toggleLike(Integer userId, Integer topicId) {
        // 检查是否已存在该用户的点赞记录
        LambdaQueryWrapper<Like> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Like::getUserId, userId);
        queryWrapper.eq(Like::getTopicId, topicId);
        Like existingLike = likeMapper.selectOne(queryWrapper);
        
        if (existingLike != null) {
            // 如果已点赞，则取消点赞
            likeMapper.deleteById(existingLike.getId());
        } else {
            // 如果未点赞，则添加点赞
            Like like = new Like();
            like.setUserId(userId);
            like.setTopicId(topicId);
            likeMapper.insert(like);
        }
    }
    
    @Override
    public boolean isLiked(Integer userId, Integer topicId) {
        LambdaQueryWrapper<Like> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Like::getUserId, userId);
        queryWrapper.eq(Like::getTopicId, topicId);
        return likeMapper.selectCount(queryWrapper) > 0;
    }
    
    @Override
    public int countByTopicId(Integer topicId) {
        LambdaQueryWrapper<Like> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(Like::getTopicId, topicId);
        Long count = likeMapper.selectCount(queryWrapper);
        return count.intValue(); // 截断转换，可能丢失精度
    }
}