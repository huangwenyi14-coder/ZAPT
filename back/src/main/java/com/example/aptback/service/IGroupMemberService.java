package com.example.aptback.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.entity.GroupMember;

import java.util.List;
import java.util.Map;

public interface IGroupMemberService {
    List<GroupMember> selectAll();

    GroupMember selectById(Long id);

    IPage<GroupMember> selectPage(Integer pageNum, Integer pageSize, Integer groupId);
    
    IPage<Map<String, Object>> selectPageWithUserInfo(Integer pageNum, Integer pageSize, Integer groupId);

    void insert(GroupMember groupMember);

    void update(GroupMember groupMember);

    void delete(Long id);
    
    List<GroupMember> selectByGroupId(Integer groupId);
    
    List<GroupMember> selectByUserId(Integer userId);
    
    boolean isUserMemberOfGroup(Integer userId, Integer groupId);
    
    GroupMember selectByUserIdAndGroupId(Integer userId, Integer groupId);
    
    void removeMemberFromGroup(Integer userId, Integer groupId) throws Exception;
    
    // 新增方法：检查用户在小组中的角色
    Map<String, Object> getUserMembershipInfo(Integer userId, Integer groupId);
}