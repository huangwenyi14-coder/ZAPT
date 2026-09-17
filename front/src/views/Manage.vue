<template>
  <div id="manage">
    <div class="site-shell">
      <!-- 顶部栏:品牌 + 用户区 -->
      <header class="topbar">
        <a class="brand" href="#/home" @click.prevent="go('/home')">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 48 48" focusable="false">
              <path d="M24 5 40 14V34L24 43 8 34V14L24 5Z" fill="currentColor" opacity=".16"/>
              <path d="M24 9 36 16V31.5L24 39 12 31.5V16L24 9Z" fill="none" stroke="currentColor" stroke-width="3"/>
              <path d="M24 15V33M16.5 19.5 24 15 31.5 19.5M16.5 28.5 24 33 31.5 28.5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </span>
          <span class="brand-title">数字弈境 · 全景式动态演化APT数据集</span>
        </a>

        <div class="topbar-actions">
          <el-dropdown v-if="isLoggedIn">
            <div class="user-button">
              <el-avatar :src="user.avatar" :size="40" fit="cover" class="topbar-avatar"></el-avatar>
              <span class="user-name">{{ user.userName }}</span>
              <i class="el-icon-arrow-down"></i>
            </div>
            <el-dropdown-menu slot="dropdown">
              <el-dropdown-item @click.native="go('/person')">个人中心</el-dropdown-item>
              <el-dropdown-item @click.native="go('/password')">修改密码</el-dropdown-item>
              <el-dropdown-item divided @click.native="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </el-dropdown>
          <template v-else>
            <button class="cc-outline-button" type="button" @click="go('/login')">登录</button>
            <button class="cc-primary-button" type="button" @click="go('/register')">免费注册</button>
          </template>
        </div>
      </header>

      <!-- 主导航 -->
      <nav class="page-nav">
        <a class="nav-card" :class="{ active: activeTab === 'home' }" href="#/home" @click.prevent="go('/home')">
          <svg viewBox="0 0 24 24" focusable="false"><path d="m3 11 9-8 9 8v9a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1v-9Z" fill="currentColor"/></svg>
          <span>首页</span>
        </a>
        <a class="nav-card" :class="{ active: activeTab === 'datasets', locked: !isLoggedIn }" href="#/datasets" @click.prevent="go('/datasets')">
          <svg viewBox="0 0 24 24" focusable="false"><path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z" fill="currentColor"/></svg>
          <span>数据集下载</span>
          <svg v-if="!isLoggedIn" class="lock-badge" viewBox="0 0 24 24" focusable="false"><path d="M7 10V8a5 5 0 0 1 10 0v2h1a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" fill="currentColor"/></svg>
        </a>
        <a class="nav-card" :class="{ active: activeTab === 'community', locked: !isLoggedIn }" href="#/community/home" @click.prevent="go('/community/home')">
          <svg viewBox="0 0 24 24" focusable="false"><path d="M12 3a9 9 0 0 1 9 9 9 9 0 0 1-9 9 9 9 0 0 1-9-9 9 9 0 0 1 9-9Zm-3.4 6.2a3.4 3.4 0 1 0 6.8 0 3.4 3.4 0 0 0-6.8 0Zm-.9 5.1c-1.5.8-2.5 2.2-2.7 3.9A7.4 7.4 0 0 0 12 20.4a7.4 7.4 0 0 0 7-5.2c-.2-1.7-1.2-3.1-2.7-3.9a5.6 5.6 0 0 1-8.6 0Z" fill="currentColor"/></svg>
          <span>社区</span>
          <svg v-if="!isLoggedIn" class="lock-badge" viewBox="0 0 24 24" focusable="false"><path d="M7 10V8a5 5 0 0 1 10 0v2h1a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" fill="currentColor"/></svg>
        </a>
      </nav>

      <!-- 页面内容:未登录时数据集/社区不渲染,仅提示登录 -->
      <main class="page-main">
        <router-view v-if="!pageLocked" @update:user="updateUser" />
        <div v-else class="lock-page">
          <div class="lock-card">
            <svg viewBox="0 0 24 24" class="lock-icon" focusable="false"><path d="M7 10V8a5 5 0 0 1 10 0v2h1a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" fill="currentColor"/></svg>
            <h3>登录后可访问{{ lockedPageName }}</h3>
            <p>该功能面向已登录用户开放,登录即可浏览与申请。</p>
            <div class="lock-actions">
              <button class="cc-primary-button" type="button" @click="go('/login')">立即登录</button>
              <a class="cc-text-button" href="#/register" @click.prevent="go('/register')">没有账号?免费注册</a>
            </div>
          </div>
        </div>
      </main>

      <footer class="site-footer">
        <span>© 2026 数字弈境 · 基于智能博弈对抗的APT攻防数据生成系统</span>
        <a href="https://attack.mitre.org/" target="_blank" rel="noopener">ATT&CK 官网</a>
      </footer>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Manage',
  data() {
    return {
      user: localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {}
    }
  },
  computed: {
    isLoggedIn() {
      return !!(this.user && this.user.token)
    },
    activeTab() {
      const path = this.$route.path
      if (path.startsWith('/community')) return 'community'
      if (path.startsWith('/datasets') || path.startsWith('/playbook')) return 'datasets'
      return 'home'
    },
    pageLocked() {
      const path = this.$route.path
      const needsLogin = path.startsWith('/datasets') || path.startsWith('/community') || path.startsWith('/playbook')
      return needsLogin && !this.isLoggedIn
    },
    lockedPageName() {
      if (this.$route.path.startsWith('/datasets')) return '数据集下载'
      if (this.$route.path.startsWith('/playbook')) return '剧本详情'
      return '社区'
    }
  },
  methods: {
    go(path) {
      if (this.$route.path === path) return
      this.$router.push(path).catch(err => {
        if (err.name !== 'NavigationDuplicated') throw err
      })
    },
    logout() {
      localStorage.removeItem("user")
      this.user = {}
      this.$router.push("/login")
    },
    updateUser(user) {
      this.user = JSON.parse(JSON.stringify(user))
    }
  }
}
</script>

<style scoped>
.site-shell {
  width: min(1440px, calc(100% - 36px));
  margin: 0 auto;
  padding-top: 14px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* ---------- 顶部栏 ---------- */
.topbar {
  min-height: 58px;
  padding: 9px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: rgba(255, 255, 255, .92);
  box-shadow: var(--shadow);
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  text-decoration: none;
  min-width: 0;
}

.brand-mark {
  flex: none;
  width: 38px;
  height: 38px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--blue);
  border: 1px solid rgba(34, 110, 232, .3);
  border-radius: 8px;
  background: rgba(34, 110, 232, .07);
}

.brand-mark svg {
  width: 28px;
  height: 28px;
}

.brand-title {
  color: var(--navy);
  font-size: 19px;
  font-weight: 850;
  letter-spacing: .5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}

.user-button {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 12px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: var(--panel-soft);
  color: var(--navy);
  cursor: pointer;
  font-size: 13px;
  font-weight: 700;
}

.topbar-avatar {
  flex: none;
}

.topbar-avatar img {
  object-position: top;
}

.user-button:hover {
  border-color: rgba(34, 110, 232, .4);
}

.user-name {
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ---------- 导航 ---------- */
.page-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.nav-card {
  flex: 1 1 160px;
  min-height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 9px;
  padding: 8px 10px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: rgba(255, 255, 255, .9);
  box-shadow: 0 8px 18px rgba(40, 83, 130, .1);
  color: var(--muted);
  font-size: 14px;
  font-weight: 800;
  text-decoration: none;
  transition: border-color .2s ease, color .2s ease;
}

.nav-card svg {
  width: 21px;
  height: 21px;
  color: var(--blue);
}

.nav-card:hover {
  color: var(--navy);
  border-color: rgba(34, 110, 232, .4);
}

.nav-card.active {
  color: #ffffff;
  border-color: rgba(34, 110, 232, .42);
  background: linear-gradient(135deg, #226ee8, #16a8c9);
  box-shadow: 0 10px 22px rgba(34, 110, 232, .22);
}

.nav-card.active svg {
  color: #ffffff;
}

.nav-card.locked {
  color: var(--faint);
  background: #f1f4f8;
  box-shadow: none;
}

.nav-card.locked svg {
  color: #9aa9b8;
}

.lock-badge {
  width: 13px !important;
  height: 13px !important;
  color: #9aa9b8 !important;
}

/* ---------- 主内容与未登录门禁 ---------- */
.page-main {
  min-height: 55vh;
}

.lock-page {
  min-height: 55vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 30px 20px;
  border: 1px dashed rgba(50, 91, 135, .25);
  border-radius: 10px;
  background: rgba(246, 250, 255, .7);
}

.lock-card {
  text-align: center;
  padding: 30px 40px;
  border: 1px solid var(--line-soft);
  border-radius: 10px;
  background: rgba(255, 255, 255, .96);
  box-shadow: 0 18px 40px rgba(40, 83, 130, .18);
}

.lock-icon {
  width: 34px;
  height: 34px;
  color: #9aa9b8;
  margin-bottom: 10px;
}

.lock-card h3 {
  margin: 0 0 8px;
  color: var(--navy);
  font-size: 17px;
}

.lock-card p {
  margin: 0 0 16px;
  color: var(--muted);
  font-size: 12.5px;
}

.lock-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

/* ---------- 页脚 ---------- */
.site-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  padding: 12px 16px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: rgba(255, 255, 255, .8);
  color: var(--muted);
  font-size: 12px;
  margin-bottom: 18px;
}

.site-footer a {
  color: var(--blue);
  text-decoration: none;
  font-weight: 700;
}

@media (max-width: 768px) {
  .brand-title {
    font-size: 14px;
  }

  .nav-card {
    flex: 1 1 100%;
  }
}
</style>
