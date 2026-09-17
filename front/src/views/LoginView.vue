<template>
  <div style="display: flex">
    <div style="flex: 6;display: flex;flex-direction: column;align-items: center;justify-content:center;background-color: #f8f9fa;min-height: 100vh">
      <div>
        <h1 style="color: #2c3e50;font-size: 40px">ZAPT Dataset Browser</h1>
      </div>
      <img src="@/assets/logo.svg" alt="" style="width: 500px;">
    </div>

    <div style="flex: 4;display: flex;flex-direction: column;align-items: center;justify-content:center;padding: 20px">
      <div>
        <h1 style="margin-bottom: 20px;color: #2c3e50;">欢迎登录</h1>
      </div>
      <div style="width: 400px">
        <el-form :model="user">
          <el-form-item prop="username">
            <el-input v-model="user.userName" size="medium" placeholder="请输入账号" prefix-icon="el-icon-user"></el-input>
          </el-form-item>
          <el-form-item prop="password">
            <el-input v-model="user.password" size="medium" type="password" placeholder="请输入密码" prefix-icon="el-icon-lock" show-password></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" style="width: 100%;height: 40px;font-size: 14px; background-color: #4a90e2; border-color: #4a90e2;" @click="login">登录</el-button>
          </el-form-item>
          <div style="display: flex;justify-content: right;font-size: 15px">
            <div style="margin-left: 10px">
              <a href="/register" style="text-decoration: none;color: #4a90e2">还没有账号？立即注册</a>
            </div>
          </div>
        </el-form>
      </div>
    </div>
  </div>
</template>

<script>
import request from "@/utils/request";

export default {
  name: 'Login',
  data() {
    return {
      user: {
        userName: '',
        password: '',
      },
    }
  },
  methods: {
    login() {
      request.post("/user/login", this.user).then(res => {
        if (res.code == '200') {
          this.$message.success('登录成功');
          localStorage.setItem("user", JSON.stringify(res.data));
          this.$router.push("/").catch(err => {
            if (err.name !== 'NavigationDuplicated') {
              throw err;
            }
          });
        } else {
          this.$message.error(res.msg);
        }
      })
    }
  }
}
</script>