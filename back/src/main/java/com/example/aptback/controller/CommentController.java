package com.example.aptback.controller;

import com.example.aptback.common.Result;
import com.example.aptback.entity.Comment;
import com.example.aptback.entity.User;
import com.example.aptback.service.ICommentService;
import com.example.aptback.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/comment")
@CrossOrigin(origins = "http://localhost:8080")
public class CommentController {
    @Autowired
    private ICommentService commentService;

    @GetMapping("/selectAll")
    public Result selectAll() {
        return Result.success(commentService.selectAll());
    }

    @GetMapping("/selectById")
    public Result selectById(@RequestParam Integer id) {
        return Result.success(commentService.selectById(id));
    }

    @GetMapping("/selectByTopicId")
    public Result selectByTopicId(@RequestParam Integer topicId) {
        return Result.success(commentService.selectByTopicId(topicId));
    }

    @GetMapping("/selectReplies")
    public Result selectReplies(@RequestParam Integer parentId) {
        return Result.success(commentService.selectReplies(parentId));
    }

    @GetMapping("/selectByAuthorId")
    public Result selectByAuthorId(@RequestParam Integer authorId) {
        return Result.success(commentService.selectByAuthorId(authorId));
    }

    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam Integer pageNum,
                             @RequestParam Integer pageSize,
                             @RequestParam(required = false) Integer topicId) {
        return Result.success(commentService.selectPage(pageNum, pageSize, topicId));
    }

    @PostMapping
    public Result insert(@RequestBody Comment comment) {
        if (comment.getId() == null) {
            commentService.insert(comment);
            return Result.success();
        } else {
            commentService.update(comment);
            return Result.success();
        }
    }

    @DeleteMapping("/delete")
    public Result delete(@RequestParam Integer id) {
        // 仅评论作者或管理员可删除
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("403", "请先登录");
        }
        Comment comment = commentService.selectById(id);
        if (comment == null) {
            return Result.error("500", "评论不存在");
        }
        boolean isAdmin = "管理员".equals(currentUser.getRole());
        if (!isAdmin && !currentUser.getId().equals(comment.getAuthorId())) {
            return Result.error("403", "仅评论作者或管理员可删除");
        }
        commentService.delete(id);
        return Result.success();
    }
}