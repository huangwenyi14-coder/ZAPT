package com.example.aptback.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.entity.UserGroup;

import java.util.List;

public interface IUserGroupService {
    List<UserGroup> selectAll();

    UserGroup selectById(Integer id);

    IPage<UserGroup> selectPage(Integer pageNum, Integer pageSize, String name);

    void insert(UserGroup userGroup);

    void update(UserGroup userGroup);

    void delete(Integer id);
    
    List<UserGroup> selectLatestGroups(Integer size);
    
    String getGroupNameById(Integer id);
    
    int getMemberCount(Integer groupId);
    
    int getTopicCount(Integer groupId);
    
    // 新增方法：彻底删除小组及其所有相关数据
    void deleteGroupAndRelatedData(Integer groupId);
}