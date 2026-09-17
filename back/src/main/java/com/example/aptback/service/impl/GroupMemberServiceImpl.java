package com.example.aptback.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.entity.GroupMember;
import com.example.aptback.mapper.GroupMemberMapper;
import com.example.aptback.service.IGroupMemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;

@Service
public class GroupMemberServiceImpl implements IGroupMemberService {
    @Autowired
    private GroupMemberMapper groupMemberMapper;
    
    @Autowired
    private com.example.aptback.mapper.UserMapper userMapper;

    @Override
    public List<GroupMember> selectAll() {
        return groupMemberMapper.selectList(null);
    }

    @Override
    public GroupMember selectById(Long id) {
        return groupMemberMapper.selectById(id);
    }

    @Override
    public IPage<GroupMember> selectPage(Integer pageNum, Integer pageSize, Integer groupId) {
        Page<GroupMember> page = new Page<>(pageNum, pageSize);
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        if (groupId != null) {
            queryWrapper.eq(GroupMember::getGroupId, groupId);
        }
        return groupMemberMapper.selectPage(page, queryWrapper);
    }
    
    @Override
    public IPage<Map<String, Object>> selectPageWithUserInfo(Integer pageNum, Integer pageSize, Integer groupId) {
        // 设置默认分页参数
        int currentPage = (pageNum != null) ? pageNum : 1;
        int size = (pageSize != null) ? pageSize : 6;
        
        // 先获取GroupMember分页数据
        Page<GroupMember> page = new Page<>(currentPage, size);
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        if (groupId != null) {
            queryWrapper.eq(GroupMember::getGroupId, groupId);
        }
        IPage<GroupMember> groupMemberPage = groupMemberMapper.selectPage(page, queryWrapper);
        
        // 构造返回结果
        Page<Map<String, Object>> resultMapPage = new Page<>();
        resultMapPage.setCurrent(groupMemberPage.getCurrent());
        resultMapPage.setSize(groupMemberPage.getSize());
        resultMapPage.setTotal(groupMemberPage.getTotal());
        
        // 查询用户信息
        List<Integer> userIds = groupMemberPage.getRecords().stream()
                .map(GroupMember::getUserId)
                .collect(Collectors.toList());
        
        List<com.example.aptback.entity.User> users = userMapper.selectBatchIds(userIds);
        
        // 构建用户信息Map
        Map<Integer, com.example.aptback.entity.User> userMap = users.stream()
                .collect(Collectors.toMap(com.example.aptback.entity.User::getId, user -> user));
        
        // 组装最终结果
        List<Map<String, Object>> resultRecords = groupMemberPage.getRecords().stream().map(groupMember -> {
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("id", groupMember.getId());
            resultMap.put("groupId", groupMember.getGroupId());
            resultMap.put("userId", groupMember.getUserId());
            
            // 获取用户信息
            com.example.aptback.entity.User user = userMap.get(groupMember.getUserId());
            if (user != null) {
                resultMap.put("username", user.getUserName());
                resultMap.put("avatar", user.getAvatar());
            } else {
                resultMap.put("username", "未知用户");
                resultMap.put("avatar", "");
            }
            
            resultMap.put("role", groupMember.getRole());
            resultMap.put("createdAt", groupMember.getCreatedAt());
            resultMap.put("updatedAt", groupMember.getUpdatedAt());
            
            return resultMap;
        }).collect(Collectors.toList());
        
        resultMapPage.setRecords(resultRecords);
        return resultMapPage;
    }

    @Override
    public void insert(GroupMember groupMember) {
        // 检查是否已存在该用户在该小组中的记录
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getGroupId, groupMember.getGroupId());
        queryWrapper.eq(GroupMember::getUserId, groupMember.getUserId());
        GroupMember existingMember = groupMemberMapper.selectOne(queryWrapper);
        
        if (existingMember != null) {
            throw new RuntimeException("该用户已在小组中");
        }
        
        groupMember.setCreatedAt(new Date());
        groupMember.setUpdatedAt(new Date());
        groupMemberMapper.insert(groupMember);
    }

    @Override
    public void update(GroupMember groupMember) {
        groupMember.setUpdatedAt(new Date());
        groupMemberMapper.updateById(groupMember);
    }

    @Override
    public void delete(Long id) {
        groupMemberMapper.deleteById(id);
    }
    
    @Override
    public List<GroupMember> selectByGroupId(Integer groupId) {
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getGroupId, groupId);
        return groupMemberMapper.selectList(queryWrapper);
    }
    
    @Override
    public List<GroupMember> selectByUserId(Integer userId) {
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getUserId, userId);
        return groupMemberMapper.selectList(queryWrapper);
    }
    
    @Override
    public boolean isUserMemberOfGroup(Integer userId, Integer groupId) {
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getUserId, userId);
        queryWrapper.eq(GroupMember::getGroupId, groupId);
        return groupMemberMapper.selectCount(queryWrapper) > 0;
    }
    
    @Override
    public GroupMember selectByUserIdAndGroupId(Integer userId, Integer groupId) {
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getUserId, userId);
        queryWrapper.eq(GroupMember::getGroupId, groupId);
        return groupMemberMapper.selectOne(queryWrapper);
    }
    
    @Override
    public void removeMemberFromGroup(Integer userId, Integer groupId) throws Exception {
        // 先查找成员信息
        GroupMember member = selectByUserIdAndGroupId(userId, groupId);
        
        if (member == null) {
            throw new Exception("用户不在该小组中");
        }

        
        if ("moderator".equals(member.getRole())) {
            throw new Exception("版主不能退出小组");
        }

        // 删除成员记录
        groupMemberMapper.deleteById(member.getId());
    }
    
    @Override
    public Map<String, Object> getUserMembershipInfo(Integer userId, Integer groupId) {
        Map<String, Object> result = new HashMap<>();
        result.put("isMember", false);
        result.put("role", "");
        
        LambdaQueryWrapper<GroupMember> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(GroupMember::getUserId, userId);
        queryWrapper.eq(GroupMember::getGroupId, groupId);
        GroupMember member = groupMemberMapper.selectOne(queryWrapper);
        
        if (member != null) {
            result.put("isMember", true);
            result.put("role", member.getRole());
        }
        
        return result;
    }
}