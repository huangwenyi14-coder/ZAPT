package com.example.aptback.service.impl;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.entity.User;
import com.example.aptback.mapper.UserMapper;
import com.example.aptback.service.IUserService;
import com.example.aptback.exception.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public List<User> selectAll() {
        List<User> list = userMapper.selectAll();
        return list;
    }

    @Override
    public User login(User user) {
        if (null == user.getUserName() || user.getUserName().equals("")){
            throw new ServiceException("用户名不能为空");
        }
        if (null == user.getPassword() || user.getPassword().equals("")){
            throw new ServiceException("密码不能为空");
        }
        //唯一校验
        LambdaQueryWrapper<User> queryWrapper= new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,user.getUserName());
        queryWrapper.eq(User::getPassword,user.getPassword());
        User one = userMapper.selectOne(queryWrapper);
        if (null == one){
            throw new ServiceException("用户名或密码错误");
        }
        return one;
    }

    @Override
    public List<User> selectSearch(String userName) {
        LambdaQueryWrapper<User> queryWrapper= new LambdaQueryWrapper<>();
        queryWrapper.like(User::getUserName,userName);
        List<User> list = userMapper.selectList(queryWrapper);
        return list;
    }

    @Override
    public IPage<User> selectPage(Integer pageNum, Integer pageSize, String userName) {
        Page<User> page = new Page<>(pageNum,pageSize);
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<User>();
        if (StrUtil.isNotBlank(userName)) {
            queryWrapper.like(User::getUserName, userName.trim());
        }
        Page<User> page1 = userMapper.selectPage(page,queryWrapper);
        return page1;
    }

    @Override
    public void insert(User user) {
        if (null == user.getUserName() || user.getUserName().equals("")){
            throw new ServiceException("用户名不能为空");
        }
        //唯一校验
        LambdaQueryWrapper<User> queryWrapper= new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,user.getUserName());
        User one = userMapper.selectOne(queryWrapper);
        if (null != one){
            throw new ServiceException("用户名已存在");
        }
        if (null == user.getPassword()){
            user.setPassword("123456");
        }
        if (null == user.getRole()){
            user.setRole("用户");
        }
        userMapper.insert(user);
    }

    @Override
    public void update(User user) {
        if (null == user.getUserName() || user.getUserName().equals("")){
            throw new ServiceException("用户名不能为空");
        }
        //唯一校验
        LambdaQueryWrapper<User> queryWrapper= new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,user.getUserName());
        if (null == user.getPassword()){
            user.setPassword("123456");
        }
        if (null == user.getRole()){
            user.setRole("用户");
        }
        userMapper.updateById(user);
    }

    @Override
    public void delete(Integer id) {
        userMapper.deleteById(id);
    }
    
    @Override
    public void password(User user) {
        // 1、非空校验
        if (null == user.getPassword() || "".equals(user.getPassword())){
            throw new ServiceException("初始密码不能为空");
        }

        if (null == user.getNewPassword() || "".equals(user.getNewPassword())){
            throw new ServiceException("新密码不能为空");
        }

        if (null == user.getConfirmPassword() || "".equals(user.getConfirmPassword())){
            throw new ServiceException("确认密码不能为空");
        }

        // 2、确认输入的原始密码跟用户信息的原始密码是否一致
        User one = userMapper.selectById(user.getId());
        if (!one.getPassword().equals(user.getPassword())){
            throw new ServiceException("原始密码输入有误");
        }

        // 3、确实新密码跟确认密码是否一致
        if (!user.getNewPassword().equals(user.getConfirmPassword())){
            throw new ServiceException("确认密码输入有误");
        }

        // 如果说确认密码跟原始密码一致，给提示
        if (one.getPassword().equals(user.getConfirmPassword())){
            throw new ServiceException("确认密码跟原始密码一致，请重新输入");
        }

        // 4、更新密码
        one.setPassword(user.getNewPassword());
        userMapper.updateById(one);
    }
    
    @Override
    public String getUserNameById(Integer id) {
        User user = userMapper.selectById(id);
        return user != null ? user.getUserName() : "未知用户";
    }
    
    @Override
    public User selectById(Integer id) {
        return userMapper.selectById(id);
    }
}