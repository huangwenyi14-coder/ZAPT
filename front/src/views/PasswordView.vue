<template>
  <div class="password-page">
    <header class="password-topbar">
      <a class="back-link" href="#/home" @click.prevent="$router.push('/home')">
        <svg viewBox="0 0 24 24" width="15" height="15"><path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
        返回首页
      </a>
      <span class="password-title">修改密码</span>
    </header>

    <el-card class="password-card">
      <el-form :model="user" label-width="80px">
        <el-form-item label="原始密码">
          <el-input v-model="user.password" show-password></el-input>
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="user.newPassword" show-password></el-input>
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="user.confirmPassword" show-password></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submit">修改密码</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script>
import request from "@/utils/request";

export default {
  name: "Password",
  data(){
    return{
      user: localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {}
    }
  },
  methods:{
    submit(){
      request.post("/user/password", this.user).then(res => {
        if (res.code == '200'){
          this.$message.success('密码修改成功');
          localStorage.removeItem("user")
          this.$router.push('/login')
        } else {
          this.$message.error(res.msg);
        }
      })
    }
  }
}
</script>

<style scoped>
.password-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px 16px;
  gap: 18px;
}

.password-topbar {
  width: min(560px, 100%);
  display: flex;
  align-items: center;
  gap: 14px;
}

.back-link {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 7px 14px;
  border-radius: 6px;
  border: 1px solid rgba(34, 110, 232, .24);
  background: #ffffff;
  color: var(--navy);
  font-size: 13px;
  font-weight: 700;
  text-decoration: none;
  box-shadow: var(--shadow);
}

.back-link:hover {
  border-color: rgba(34, 110, 232, .45);
  color: var(--blue);
}

.password-title {
  color: var(--navy);
  font-size: 18px;
  font-weight: 850;
}

.password-card {
  width: min(560px, 100%);
}
</style>
