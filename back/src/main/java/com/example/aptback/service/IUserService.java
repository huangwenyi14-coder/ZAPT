package com.example.aptback.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.example.aptback.entity.User;

import java.util.List;

public interface IUserService {
    List<User> selectAll();

    User login(User user);

    List<User> selectSearch(String userName);

    IPage<User> selectPage(Integer pageNum, Integer pageSize, String userName);

    void insert(User user);

    void update(User user);

    void delete(Integer id);

    void password(User user);
    
    String getUserNameById(Integer id);
    
    User selectById(Integer id);
}