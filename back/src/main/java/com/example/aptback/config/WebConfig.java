package com.example.aptback.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 配置jwt的拦截器规则
        registry.addInterceptor(jwtInterceptor())
        // 拦截所有的请求路径
        .addPathPatterns("/**")
        // 放行以下接口
        .excludePathPatterns("/user/login", "/user/register","/file/**");
    }

    @Bean
    public JwtInterceptor jwtInterceptor() {
        return new JwtInterceptor();
    }
}