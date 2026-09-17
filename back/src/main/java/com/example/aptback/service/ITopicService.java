package com.example.aptback.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.entity.Topic;

import java.util.List;

public interface ITopicService {
    List<Topic> selectAll();

    Topic selectById(Integer id);

    IPage<Topic> selectPage(Integer pageNum, Integer pageSize, Integer groupId, String title);

    void insert(Topic topic);

    void update(Topic topic);

    void delete(Integer id);
    
    List<Topic> selectByGroupId(Integer groupId);
    
    List<Topic> selectByAuthorId(Integer authorId);
    
    List<Topic> selectLatestByGroupId(Integer groupId, Integer size);
    
    List<Topic> selectTopTopics(Integer size);
}