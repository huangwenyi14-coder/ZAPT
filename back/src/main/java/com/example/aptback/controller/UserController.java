package com.example.aptback.controller;

import com.example.aptback.common.Result;
import com.example.aptback.entity.User;
import com.example.aptback.service.IUserService;
import com.example.aptback.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "http://localhost:8080")
public class UserController {
    @Autowired
    private IUserService userService;
    
    @GetMapping("/selectAll")
    public Result selectAll(){
        if (!isAdmin()) {
            return Result.error("403", "仅管理员可查看用户列表");
        }
        return Result.success(userService.selectAll());
    }

    @GetMapping("/selectSearch")
    public Result selectSearch(@RequestParam String userName){
        if (!isAdmin()) {
            return Result.error("403", "仅管理员可查看用户列表");
        }
        return Result.success(userService.selectSearch(userName));
    }

    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam Integer pageNum,
                             @RequestParam Integer pageSize,
                             @RequestParam String userName){
        if (!isAdmin()) {
            return Result.error("403", "仅管理员可查看用户列表");
        }
        return Result.success(userService.selectPage(pageNum,pageSize,userName));
    }

    @PostMapping
    public Result insert(@RequestBody User user){
        // 用户管理(新增/编辑账号)仅管理员可操作,防止普通用户借通用保存接口改他人资料或造管理员账号
        if (!isAdmin()) {
            return Result.error("403", "仅管理员可操作用户管理");
        }
        if (null == user.getId()) {
            userService.insert(user);
            return Result.success();
        }else{
            userService.update(user);
            return Result.success();
        }
    }

    @DeleteMapping("/delete")
    public Result delete(@RequestParam Integer id){
        if (!isAdmin()) {
            return Result.error("403", "仅管理员可删除用户");
        }
        userService.delete(id);
        return Result.success();
    }
    
    @PostMapping("/login")
    public Result login(@RequestBody User user){
        User one = userService.login(user);
        // 生成token
        String token = TokenUtils.createToken(one.getId().toString(), one.getPassword());
        
        // 构建只包含必要信息的返回对象，避免返回密码等敏感信息
        Map<String, Object> result = new HashMap<>();
        result.put("id", one.getId());
        result.put("userName", one.getUserName());
        result.put("role", one.getRole());
        result.put("avatar", one.getAvatar());
        result.put("token", token);
        
        return Result.success(result);
    }
    
    @PostMapping("/register")
    public Result register(@RequestBody User user){
        userService.insert(user);
        return Result.success();
    }

    @PostMapping("/updateUserInfo")
    public Result updateUserInfo(@RequestBody User user){
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        // 只能修改自己的资料:以token解析出的身份为准,忽略请求体中的id,防止水平越权改他人账号
        user.setId(currentUser.getId());
        // 角色不允许通过此接口修改,防止普通用户自助提权为管理员
        user.setRole(currentUser.getRole());
        // 密码不在此接口修改(须走/password接口并验证原密码),始终回填库中原密码
        User dbUser = userService.selectById(currentUser.getId());
        if (dbUser == null) {
            return Result.error("500", "用户不存在");
        }
        user.setPassword(dbUser.getPassword());
        userService.update(user);
        User one = userService.selectById(currentUser.getId());
        String token = TokenUtils.createToken(one.getId().toString(), one.getPassword());
        Map<String, Object> result = new HashMap<>();
        result.put("id", one.getId());
        result.put("userName", one.getUserName());
        result.put("role", one.getRole());
        result.put("avatar", one.getAvatar());
        result.put("token", token);
        return Result.success(result);
    }
    
    @PostMapping("/password")
    public Result password(@RequestBody User user){
        // 仅可修改自己的密码:以token身份为准,防止改他人密码
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        if (!currentUser.getId().equals(user.getId())) {
            return Result.error("403", "仅可修改自己的密码");
        }
        userService.password(user);
        return Result.success();
    }

    /**
     * 判断当前登录用户是否为管理员
     */
    private boolean isAdmin() {
        User currentUser = TokenUtils.getCurrentUser();
        return currentUser != null && "管理员".equals(currentUser.getRole());
    }
    
    @GetMapping("/selectById")
    public Result selectById(@RequestParam Integer id) {
        User user = userService.selectById(id);
        if (user != null) {
            // 构建只包含必要信息的返回对象，避免返回密码等敏感信息
            Map<String, Object> result = new HashMap<>();
            result.put("id", user.getId());
            result.put("userName", user.getUserName());
            result.put("role", user.getRole());
            result.put("avatar", user.getAvatar());
            return Result.success(result);
        } else {
            return Result.error("用户不存在");
        }
    }
}