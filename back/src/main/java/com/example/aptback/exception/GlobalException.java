package com.example.aptback.exception;

import com.example.aptback.common.Result;
import com.example.aptback.exception.ServiceException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

// @ControllerAdvice 是Spring的注解，用于定义全局异常处理器，会拦截所有控制器(Controller)抛出的异常
@ControllerAdvice
public class GlobalException {
    /**
     * 处理自定义业务异常(ServiceException)
     * 当项目中抛出ServiceException时，会被该方法捕获并处理
     *
     * @param e 捕获到的业务异常对象，包含错误码和错误信息
     * @return 统一的响应结果(Result)，包含错误码和错误信息，用于返回给前端
     */
    @ExceptionHandler(ServiceException.class) // 指定该方法处理ServiceException类型的异常
    @ResponseBody // 将返回的Result对象转换为JSON格式响应给前端
    public Result serviceException(ServiceException e) {
        // 直接使用异常中携带的错误码和信息构建响应结果
        return Result.error(e.getCode(), e.getMessage());
    }

    /**
     * 处理所有未被特定异常处理器捕获的异常(全局默认异常处理)
     * 当项目中抛出非ServiceException的异常时，会被该方法捕获（如空指针、数据库异常等）
     *
     * @param e 捕获到的异常对象
     * @return 统一的响应结果(Result)，返回默认的系统错误信息，避免暴露具体异常细节
     */
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public Result globalException(Exception e) {
        // 打印异常堆栈信息，便于开发和运维排查问题（生产环境可考虑输出到日志系统）
        e.printStackTrace();
        // 返回默认的系统错误响应（错误码500，提示信息"系统错误"）
        return Result.error("500", "系统错误");
    }
}