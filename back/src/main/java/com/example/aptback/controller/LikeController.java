package com.example.aptback.controller;

import com.example.aptback.common.Result;
import com.example.aptback.entity.Like;
import com.example.aptback.service.ILikeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/like")
@CrossOrigin(origins = "http://localhost:8080")
public class LikeController {
    @Autowired
    private ILikeService likeService;

    @PostMapping("/toggle")
    public Result toggleLike(@RequestBody Like like) {
        likeService.toggleLike(like.getUserId(), like.getTopicId());
        return Result.success();
    }

    @GetMapping("/isLiked")
    public Result isLiked(@RequestParam Integer userId, @RequestParam Integer topicId) {
        boolean liked = likeService.isLiked(userId, topicId);
        return Result.success(liked);
    }

    @GetMapping("/count")
    public Result countByTopicId(@RequestParam Integer topicId) {
        int count = likeService.countByTopicId(topicId);
        return Result.success(count);
    }
}