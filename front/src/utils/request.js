import axios from 'axios'
import ElementUI from 'element-ui';
import router from '@/router'
// 创建一个新的axios实例
const request = axios.create({
    baseURL: '/api',   // 后端接口基础地址（由 Nginx 反向代理到 :9999）
    timeout: 5000
})

// 用于跟踪是否已经显示过token错误消息
let tokenErrorShown = false;

// request 拦截器，可以自请求发送前对请求做一些处理，比如统一加token，对请求参数统一加密
request.interceptors.request.use(config => {
    // 设置默认Content-Type为JSON格式（适用于大多数POST/PUT请求）
    config.headers['Content-Type'] = 'application/json;charset=utf-8';
    const user = localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {}
    config.headers['token'] = user.token
    return config
}, error => {
    return Promise.reject(error)
});

// 响应拦截器（接口响应后的处理）作用：统一处理响应数据
request.interceptors.response.use(
    response => {
        let res = response.data;

        // 兼容服务端返回的字符串类型数据（如果后端返回JSON字符串，自动解析为对象）
        if (typeof res === 'string') {
            res = res ? JSON.parse(res) : res
        }
        if (res.code === '401') {
            // 只有在未显示过错误消息时才显示
            if (!tokenErrorShown) {
                ElementUI.Message.error(res.msg)
                tokenErrorShown = true;
                // 设置一个定时器，一段时间后重置标志位
                setTimeout(() => {
                    tokenErrorShown = false;
                }, 5000); // 5秒内不再显示相同错误
            }
            router.push('/login')
        }
        return res;
    }, error => {
        return Promise.reject(error)
    }
)

export default request