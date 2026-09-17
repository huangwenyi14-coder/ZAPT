package com.example.aptback.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.aptback.entity.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

public interface UserMapper extends BaseMapper<User> {


    // 查询所有
    List<User> selectAll();
}