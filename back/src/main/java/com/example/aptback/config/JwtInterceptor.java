package com.example.aptback.config;

import cn.hutool.core.util.StrUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.aptback.entity.User;
import com.example.aptback.exception.ServiceException;
import com.example.aptback.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * JWT认证拦截器
 * 作用：拦截请求并验证JWT令牌的有效性，实现基于令牌的身份认证
 * 仅允许携带有效令牌的请求访问受保护接口，或标记了@AuthAccess注解的接口
 */
public class JwtInterceptor implements HandlerInterceptor {

    @Autowired
    private UserMapper userMapper; // 用户数据访问接口，用于查询用户信息验证身份

    /**
     * 请求处理前执行的拦截方法
     * 验证请求中的JWT令牌，通过则放行，否则抛出认证异常
     *
     * @param request  HTTP请求对象，用于获取请求头或参数中的token
     * @param response HTTP响应对象
     * @param handler  拦截到的处理器（方法或资源）
     * @return boolean 认证通过返回true（放行），否则返回false（拦截）
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // 1. 从请求头或URL参数中获取token
        String token = request.getHeader("token");  // 优先从请求头获取token
        if (StrUtil.isBlank(token)) {
            token = request.getParameter("token");  // 若请求头无token，则从URL参数获取
        }

        // 2. 验证token是否存在
        if (StrUtil.isBlank(token)) {
            // 无token时抛出未登录异常
            throw new ServiceException("401", "token验证失败，请重新登录");
        }

        // 3. 解析token获取用户ID
        String userId;
        try {
            // 从token的受众（audience）中获取第一个参数作为用户ID
            // 注：此处依赖生成token时的格式，需与token生成逻辑保持一致
            userId = JWT.decode(token).getAudience().get(0);
        } catch (JWTDecodeException e) {
            // token解析失败（格式错误），抛出未登录异常
            throw new ServiceException("401", "token验证失败，请重新登录");
        }

        // 4. 根据用户ID查询数据库验证用户是否存在
        User user = userMapper.selectById(Integer.valueOf(userId));
        if (user == null) {
            // 用户不存在，抛出未登录异常
            throw new ServiceException("401", "用户不存在，请重新登录");
        }

        // 5. 验证token的有效性（使用用户密码作为密钥验证签名）
        try {
            // 创建验证器：使用用户密码作为HMAC256算法的密钥（需与生成token时的密钥一致）
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(user.getPassword())).build();
            jwtVerifier.verify(token); // 验证token的签名和有效期等
        } catch (JWTVerificationException e) {
            // token验证失败（签名错误、已过期等），抛出未登录异常
            throw new ServiceException("401", "token验证失败，请重新登录");
        }

        // 6. 所有验证通过，放行请求
        return true;
    }
}