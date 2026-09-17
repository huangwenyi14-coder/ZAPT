package com.example.aptback.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.common.Result;
import com.example.aptback.entity.User;
import com.example.aptback.entity.UserGroup;
import com.example.aptback.service.IUserGroupService;
import com.example.aptback.service.ITopicService;
import com.example.aptback.service.IUserService;
import com.example.aptback.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/group")
@CrossOrigin(origins = "http://localhost:8080")
public class UserGroupController {

    @Autowired
    private IUserGroupService userGroupService;
    
    @Autowired
    private ITopicService topicService;
    
    @Autowired
    private IUserService userService;
    
    @Autowired
    private com.example.aptback.mapper.CommentMapper commentMapper;
    
    @Autowired
    private com.example.aptback.mapper.LikeMapper likeMapper;

    @GetMapping("/selectAll")
    public Result selectAll() {
        return Result.success(userGroupService.selectAll());
    }

    @GetMapping("/selectById")
    public Result selectById(@RequestParam("id") Integer id) {
        UserGroup group = userGroupService.selectById(id);
        if (group == null) {
            return Result.error("404", "小组不存在");
        }
        
        // 添加统计信息
        int memberCount = userGroupService.getMemberCount(id);
        int topicCount = userGroupService.getTopicCount(id);
        group.setMemberCount(memberCount);
        group.setTopicCount(topicCount);
        
        return Result.success(group);
    }

    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum,
                             @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
                             @RequestParam(value = "name", required = false) String name) {
        IPage<UserGroup> page = userGroupService.selectPage(pageNum, pageSize, name);
        List<UserGroup> records = page.getRecords();
        
        // 为每条记录添加统计信息
        for (UserGroup group : records) {
            int groupId = group.getId();
            int memberCount = userGroupService.getMemberCount(groupId);
            int topicCount = userGroupService.getTopicCount(groupId);
            group.setMemberCount(memberCount);
            group.setTopicCount(topicCount);
        }
        
        return Result.success(page);
    }
    
    @GetMapping("/latest")
    public Result selectLatestGroups() {
        List<UserGroup> groups = userGroupService.selectLatestGroups(6);
        return Result.success(groups);
    }
    
    @GetMapping("/latestTopics")
    public Result selectLatestTopicsByPage(@RequestParam("id") Integer id,
                                          @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum,
                                          @RequestParam(value = "pageSize", defaultValue = "5") Integer pageSize) {
        IPage<com.example.aptback.entity.Topic> page = topicService.selectPage(pageNum, pageSize, id, null);
        List<com.example.aptback.entity.Topic> records = page.getRecords();
        
        // 为每条记录添加额外信息
        for (com.example.aptback.entity.Topic topic : records) {
            // 添加作者名称
            String authorName = userService.getUserNameById(topic.getAuthorId());
            topic.setAuthorName(authorName);
            
            // 添加评论数
            LambdaQueryWrapper<com.example.aptback.entity.Comment> commentQueryWrapper = new LambdaQueryWrapper<>();
            commentQueryWrapper.eq(com.example.aptback.entity.Comment::getTopicId, topic.getId());
            int commentCount = commentMapper.selectCount(commentQueryWrapper).intValue();
            topic.setCommentCount(commentCount);
            
            // 添加点赞数
            LambdaQueryWrapper<com.example.aptback.entity.Like> likeQueryWrapper = new LambdaQueryWrapper<>();
            likeQueryWrapper.eq(com.example.aptback.entity.Like::getTopicId, topic.getId());
            int likeCount = likeMapper.selectCount(likeQueryWrapper).intValue();
            topic.setLikeCount(likeCount);
        }
        
        return Result.success(page);
    }

    @PostMapping
    public Result save(@RequestBody UserGroup userGroup) {
        try {
            if (userGroup.getId() == null) {
                userGroupService.insert(userGroup);
            } else {
                userGroupService.update(userGroup);
            }
            return Result.success();
        } catch (Exception e) {
            return Result.error("500", e.getMessage());
        }
    }

    @DeleteMapping("/delete")
    public Result delete(@RequestParam("id") Integer id) {
        try {
            String denied = checkGroupDeletePermission(id);
            if (denied != null) return Result.error("403", denied);
            userGroupService.delete(id);
            return Result.success();
        } catch (Exception e) {
            return Result.error("500", e.getMessage());
        }
    }

    // 新增接口：彻底删除小组及其所有相关数据
    @DeleteMapping("/deleteCompletely")
    public Result deleteCompletely(@RequestParam("id") Integer id) {
        try {
            String denied = checkGroupDeletePermission(id);
            if (denied != null) return Result.error("403", denied);
            userGroupService.deleteGroupAndRelatedData(id);
            return Result.success();
        } catch (Exception e) {
            return Result.error("500", e.getMessage());
        }
    }

    /**
     * 删除权限校验:仅小组创建者或管理员可删除,返回 null 表示允许
     */
    private String checkGroupDeletePermission(Integer groupId) {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return "请先登录";
        }
        UserGroup group = userGroupService.selectById(groupId);
        if (group == null) {
            return "小组不存在";
        }
        boolean isAdmin = "管理员".equals(currentUser.getRole());
        boolean isCreator = currentUser.getId().equals(group.getCreatorId());
        if (!isAdmin && !isCreator) {
            return "仅小组创建者或管理员可删除";
        }
        return null;
    }
}