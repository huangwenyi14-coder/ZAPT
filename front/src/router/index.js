import Vue from 'vue'
import VueRouter from 'vue-router'
import HomeView from '../views/HomeView.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Manage',
    component: () => import('@/views/Manage.vue'),
    redirect: '/home',
    children: [
      {
        path: 'home',
        name: 'home',
        component: HomeView
      },
      {
        path: 'datasets',
        name: 'Datasets',
        component: () => import('@/views/DatasetView.vue')
      },
      {
        path: 'playbook/:id',
        name: 'PlaybookDetail',
        component: () => import('@/views/PlaybookDetailView.vue')
      },
      {
        path: 'browser',
        name: 'Browser',
        component: () => import('@/views/BrowserView.vue')
      },
      {
        path: 'features',
        name: 'Features',
        component: () => import('@/views/FeaturesView.vue')
      },
      {
        path: 'leaderboard',
        name: 'Leaderboard',
        component: () => import('@/views/LeaderboardView.vue')
      },
      {
        path: 'citations',
        name: 'PaperCitations',
        component: () => import('@/views/CitationsView.vue')
      },
      {
        path: 'community/home',
        name: 'CommunityHome',
        component: () => import('@/views/CommunityView.vue')
      },
      {
        path: 'community/all',
        name: 'CommunityAll',
        component: () => import('@/views/CommunityGroupAllView.vue')
      },
      {
        path: 'community/me',
        name: 'CommunityMe',
        component: () => import('@/views/CommunityGroupMeView.vue')
      },
      {
        path: 'community/group/:id',
        name: 'CommunityGroupDetail',
        component: () => import('@/views/CommunityGroupDetailView.vue')
      },
      {
        path: 'community/topic/:id',
        name: 'CommunityGroupPost',
        component: () => import('@/views/CommunityGroupPostView.vue')
      },
      {
        path: 'description',
        name: 'Description',
        component: () => import('@/views/DescriptionView.vue')
      },
      {
        path: 'cases',
        name: 'Cases',
        component: () => import('@/views/CasesView.vue')
      }
    ]
  },
  {
    path: '/person',
    name: 'Person',
    component: () => import('@/views/PersonView.vue')
  },
  {
    path: '/password',
    name: 'Password',
    component: () => import('@/views/PasswordView.vue')
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/LoginView.vue')
  },
  {
    path: '/register',
    name: 'Register',
    component: () => import('@/views/RegisterView.vue')
  },
  {
    path: '/user',
    name: 'User',
    component: () => import('@/views/UserView.vue')
  }
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

// 全局路由守卫:/user 用户管理页仅管理员可进入,其他角色重定向回首页
router.beforeEach((to, from, next) => {
  const user = localStorage.getItem('user') ? JSON.parse(localStorage.getItem('user')) : null
  if (to.path === '/user' && (!user || user.role !== '管理员')) {
    next('/')
  } else {
    next()
  }
})
// router/index.js
const originalPush = VueRouter.prototype.push
VueRouter.prototype.push = function push(location) {
  return originalPush.call(this, location).catch(err => {
    if (err.name !== 'NavigationDuplicated' && !err.message.includes('Navigation cancelled')) {
      throw err
    }
  })
}


export default router