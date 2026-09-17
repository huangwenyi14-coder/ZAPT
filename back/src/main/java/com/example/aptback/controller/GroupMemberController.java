package com.example.aptback.controller;

import com.example.aptback.common.Result;
import com.example.aptback.entity.GroupMember;
import com.example.aptback.service.IGroupMemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/group-member")
@CrossOrigin(origins = "http://localhost:8080")
public class GroupMemberController {
    @Autowired
    private IGroupMemberService groupMemberService;

    @GetMapping("/selectAll")
    public Result selectAll() {
        return Result.success(groupMemberService.selectAll());
    }

    @GetMapping("/selectById")
    public Result selectById(@RequestParam("id") Long id) {
        return Result.success(groupMemberService.selectById(id));
    }

    @GetMapping("/selectByGroupId")
    public Result selectByGroupId(@RequestParam("groupId") Integer groupId) {
        return Result.success(groupMemberService.selectByGroupId(groupId));
    }

    @GetMapping("/selectByUserId")
    public Result selectByUserId(@RequestParam("userId") Integer userId) {
        return Result.success(groupMemberService.selectByUserId(userId));
    }

    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam(value = "pageNum", required = false) Integer pageNum,
                             @RequestParam(value = "pageSize", required = false) Integer pageSize,
                             @RequestParam(value = "groupId", required = false) Integer groupId) {
        return Result.success(groupMemberService.selectPageWithUserInfo(pageNum, pageSize, groupId));
    }
    
    @GetMapping("/membershipInfo")
    public Result getUserMembershipInfo(@RequestParam("userId") Integer userId, @RequestParam("groupId") Integer groupId) {
        Map<String, Object> membershipInfo = groupMemberService.getUserMembershipInfo(userId, groupId);
        return Result.success(membershipInfo);
    }

    @PostMapping
    public Result insert(@RequestBody GroupMember groupMember) {
        try {
            groupMemberService.insert(groupMember);
            return Result.success();
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }
    
    @DeleteMapping("/removeMember")
    public Result removeMember(@RequestParam("userId") Integer userId, @RequestParam("groupId") Integer groupId) {
        try {
            groupMemberService.removeMemberFromGroup(userId, groupId);
            return Result.success();
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    @DeleteMapping("/delete")
    public Result delete(@RequestParam("id") Long id) {
        groupMemberService.delete(id);
        return Result.success();
    }
}