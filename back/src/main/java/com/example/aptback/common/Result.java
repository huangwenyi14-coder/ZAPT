package com.example.aptback.common;

public class Result {
    public static final String SUCCESS = "200";
    public static final String ERROR = "500";
    private String code;
    private String msg;
    private Object data;
    public static Result success() {
        Result result = new Result();
        result.setCode(SUCCESS);
        result.setMsg("请求成功");
        return result;
    }
    public static Result success(Object data) {
        Result result = new Result();
        result.setCode(SUCCESS);
        result.setMsg("请求成功");
        result.setData(data);
        return result;
    }
    public static Result error() {
        Result result = new Result();
        result.setCode(ERROR);
        result.setMsg("请求失败");
        return result;
    }
    public static Result error(String msg) {
        Result result = new Result();
        result.setCode(ERROR);
        result.setMsg(msg);
        return result;
    }public static Result error(String code,String msg) {
        Result result = new Result();
        result.setCode(code);
        result.setMsg(msg);
        return result;
    }
    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
