package com.example.aptback.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * 跨域跨配置类：解决跨域资源共享（CORS）配置
 * 作用：解决前后端分离架构中，前端页面与后端接口不在同一域名下时的跨域访问问题
 *
 * @Configuration：标识该类为Spring配置类，会被Spring自动扫描并加载
 */
@Configuration
public class CorsConfig {

    // 当前跨域请求最大有效时长（单位：秒），这里默认设置为1天（24*60*60秒）
    // 用于指定预检请求（OPTIONS请求）的缓存时间，过期前无需再次发送预检请求
    private static final long MAX_AGE = 24 * 60 * 60;

    /**
     * 创建CORS过滤器Bean，用于处理跨域请求
     * Spring会将该Bean注册到过滤器链中，对所有请求进行跨域校验
     *
     * @Bean：将方法返回的对象注册为Spring容器中的Bean
     * @return CorsFilter 跨域过滤器实例
     */
    @Bean
    public CorsFilter corsFilter() {
        // 创建基于URL的跨域配置源，用于针对不同URL路径设置不同的跨域规则
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // 创建跨域配置对象，设置允许的跨域规则
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // 1. 设置允许访问的源地址（Origin）
        // "*"表示允许所有域名访问，生产环境中建议指定具体域名（如"http://localhost:8080"）以提高安全性
        corsConfiguration.addAllowedOrigin("*");

        // 2. 设置允许的请求头（Header）
        // "*"表示允许所有请求头，包括自定义头（如Token、Authorization等）
        corsConfiguration.addAllowedHeader("*");

        // 3. 设置允许的HTTP请求方法（Method）
        // "*"表示允许所有HTTP方法（GET、POST、PUT、DELETE、OPTIONS等）
        corsConfiguration.addAllowedMethod("*");

        // 设置预检请求的缓存时长（单位：秒）
        corsConfiguration.setMaxAge(MAX_AGE);

        // 4. 为所有接口路径（/**表示匹配所有URL）注册跨域配置
        // 即所有接口都应用上述跨域规则
        source.registerCorsConfiguration("/**", corsConfiguration);

        // 创建并返回CORS过滤器实例
        return new CorsFilter(source);
    }
}