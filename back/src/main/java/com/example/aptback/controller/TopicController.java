package com.example.aptback.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.common.Result;
import com.example.aptback.entity.Comment;
import com.example.aptback.entity.Like;
import com.example.aptback.entity.Topic;
import com.example.aptback.entity.User;
import com.example.aptback.service.ICommentService;
import com.example.aptback.service.ILikeService;
import com.example.aptback.service.ITopicService;
import com.example.aptback.service.IUserGroupService;
import com.example.aptback.service.IUserService;
import com.example.aptback.mapper.CommentMapper;
import com.example.aptback.mapper.LikeMapper;
import com.example.aptback.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/topic")
public class TopicController {

    @Autowired
    private ITopicService topicService;
    
    @Autowired
    private IUserService userService;
    
    @Autowired
    private IUserGroupService userGroupService;
    
    @Autowired
    private CommentMapper commentMapper;
    
    @Autowired
    private LikeMapper likeMapper;

    @GetMapping("/selectAll")
    public Result selectAll() {
        List<Topic> topics = topicService.selectAll();
        return Result.success(topics);
    }

    @GetMapping("/selectById")
    public Result selectById(@RequestParam Integer id) {
        Topic topic = topicService.selectById(id);
        if (topic == null) {
            return Result.error("404", "话题不存在");
        }
        
        // 添加作者名称
        String authorName = userService.getUserNameById(topic.getAuthorId());
        topic.setAuthorName(authorName);
        
        return Result.success(topic);
    }

    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam Integer pageNum,
                             @RequestParam Integer pageSize,
                             @RequestParam(required = false) Integer groupId,
                             @RequestParam(required = false) String title) {
        IPage<Topic> page = topicService.selectPage(pageNum, pageSize, groupId, title);
        List<Topic> records = page.getRecords();
        
        // 为每条记录添加额外信息
        for (Topic topic : records) {
            // 添加小组名称
            String groupName = userGroupService.getGroupNameById(topic.getGroupId());
            topic.setGroupName(groupName);
            
            // 添加作者名称
            String authorName = userService.getUserNameById(topic.getAuthorId());
            topic.setAuthorName(authorName);
        }
        
        return Result.success(page);
    }

    @PostMapping
    public Result save(@RequestBody Topic topic) {
        try {
            if (topic.getId() == null) {
                topicService.insert(topic);
            } else {
                topicService.update(topic);
            }
            return Result.success();
        } catch (Exception e) {
            return Result.error("500", e.getMessage());
        }
    }

    @DeleteMapping("/delete")
    public Result delete(@RequestParam Integer id) {
        try {
            // 仅话题作者或管理员可删除
            User currentUser = TokenUtils.getCurrentUser();
            Topic topic = topicService.selectById(id);
            if (currentUser == null) {
                return Result.error("403", "请先登录");
            }
            if (topic == null) {
                return Result.error("500", "话题不存在");
            }
            boolean isAdmin = "管理员".equals(currentUser.getRole());
            if (!isAdmin && !currentUser.getId().equals(topic.getAuthorId())) {
                return Result.error("403", "仅话题作者或管理员可删除");
            }
            topicService.delete(id);
            return Result.success();
        } catch (Exception e) {
            return Result.error("500", e.getMessage());
        }
    }
    
    @GetMapping("/top")
    public Result selectTopTopics() {
        List<Topic> topics = topicService.selectTopTopics(6);
        List<Map<String, Object>> result = new ArrayList<>();
        
        for (Topic topic : topics) {
            Map<String, Object> item = new HashMap<>();
            item.put("id", topic.getId());
            item.put("title", topic.getTitle());
            item.put("content", topic.getContent());
            item.put("groupName", userGroupService.getGroupNameById(topic.getGroupId()));
            item.put("authorName", userService.getUserNameById(topic.getAuthorId()));
            
            // 获取评论数
            LambdaQueryWrapper<Comment> commentQueryWrapper = new LambdaQueryWrapper<>();
            commentQueryWrapper.eq(Comment::getTopicId, topic.getId());
            int commentCount = commentMapper.selectCount(commentQueryWrapper).intValue();
            item.put("commentCount", commentCount);
            
            // 获取点赞数
            LambdaQueryWrapper<Like> likeQueryWrapper = new LambdaQueryWrapper<>();
            likeQueryWrapper.eq(Like::getTopicId, topic.getId());
            int likeCount = likeMapper.selectCount(likeQueryWrapper).intValue();
            item.put("likeCount", likeCount);
            
            result.add(item);
        }
        
        return Result.success(result);
    }
    
    @GetMapping("/selectByGroupId")
    public Result selectByGroupId(@RequestParam Integer groupId) {
        List<Topic> topics = topicService.selectByGroupId(groupId);
        // 为每条记录添加作者名称
        for (Topic topic : topics) {
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
        return Result.success(topics);
    }
    
    @GetMapping("/selectByAuthorId")
    public Result selectByAuthorId(@RequestParam Integer authorId) {
        List<Topic> topics = topicService.selectByAuthorId(authorId);
        // 为每条记录添加作者名称
        for (Topic topic : topics) {
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
        return Result.success(topics);
    }
}