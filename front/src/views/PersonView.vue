<template>
  <div class="person-page">
    <header class="person-topbar">
      <a class="back-link" href="#/home" @click.prevent="$router.push('/home')">
        <svg viewBox="0 0 24 24" width="15" height="15"><path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
        返回首页
      </a>
      <span class="person-title">个人中心</span>
    </header>

    <el-card class="person-card">
      <el-form label-width="80px">
        <el-form-item label="姓名">
          <el-input v-model="user.userName" disabled></el-input>
        </el-form-item>
        <el-form-item label="权限">
          <el-input v-model="user.role" disabled></el-input>
        </el-form-item>
        <el-form-item label="头像">
          <el-upload
              action="/api/file/uploadAvatar"
              :headers="{token: user.token}"
              :on-success="handleAvatarSuccess"
              :show-file-list="false"
              accept="image/*"
          >
            <img v-if="user.avatar" :src="user.avatar" class="avatar-preview"/>
            <div v-else class="avatar-preview avatar-empty">点击上传</div>
          </el-upload>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submit">保存</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="person-card">
      <div slot="header" class="myds-head">
        <b>我的数据集</b><span class="myds-count">共 {{ myDatasets.length }} 个</span>
        <span class="myds-tip">提交生成申请后在此查看进度与下载;生成中的记录每 5 秒自动刷新</span>
      </div>
      <el-table :data="pagedDatasets" style="width:100%" empty-text=" 暂无生成记录,去首页提交生成申请 ">
        <el-table-column label="生成内容(提示词)" min-width="420" show-overflow-tooltip>
          <template slot-scope="scope">
            <span class="myds-events">{{ scope.row.genEvents }}</span>
          </template>
        </el-table-column>
        <el-table-column label="提交时间" width="165" class-name="time-nw">
          <template slot-scope="scope">{{ scope.row.createdAt }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template slot-scope="scope">
            <el-tag v-if="scope.row.genStatus === 0" size="small" type="warning">生成中…</el-tag>
            <el-tag v-else-if="scope.row.genStatus === 1" size="small" type="success">已生成</el-tag>
            <el-tooltip v-else :content="briefReason(scope.row)" placement="top">
              <el-tag size="small" type="danger">生成失败</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120">
          <template slot-scope="scope">
            <el-button v-if="scope.row.genStatus === 1" size="mini" type="primary" plain @click="downloadDs(scope.row)">打包下载</el-button>
            <el-button v-else-if="scope.row.genStatus === 2" size="mini" type="text" @click="failRow = scope.row; failVisible = true">查看原因</el-button>
            <el-button v-else size="mini" type="text" disabled>生成后可下载</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="myds-pager" v-if="myDatasets.length > dsPageSize">
        <el-pagination background layout="total, prev, pager, next" :total="myDatasets.length"
                       :page-size="dsPageSize" :current-page.sync="dsPage"></el-pagination>
      </div>
    </el-card>

    <!-- 失败原因弹窗 -->
    <el-dialog title="生成失败原因" :visible.sync="failVisible" width="46%">
      <p class="fail-brief" v-if="failRow">{{ briefReason(failRow) }}</p>
      <p class="fail-tip">以下为生成引擎完整日志(末尾部分),便于定位问题:</p>
      <pre class="fail-log">{{ failRow ? failRow.genLog : '' }}</pre>
    </el-dialog>
  </div>
</template>

<script>
import request from "@/utils/request";

export default {
  name: "Person",
  data(){
    return{
      user: localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {},
      myDatasets: [],
      pollTimer: null,
      dsPage: 1,
      dsPageSize: 10,
      failVisible: false,
      failRow: null
    }
  },
  computed: {
    pagedDatasets() {
      const start = (this.dsPage - 1) * this.dsPageSize
      return this.myDatasets.slice(start, start + this.dsPageSize)
    }
  },
  mounted() {
    this.loadMyDatasets()
    this.pollTimer = setInterval(() => {
      // 仍有生成中的记录才刷新,减少无谓请求
      if (this.myDatasets.some(d => d.genStatus === 0)) this.loadMyDatasets()
    }, 5000)
  },
  beforeDestroy() {
    if (this.pollTimer) clearInterval(this.pollTimer)
  },
  methods:{
    briefReason(row) {
      if (!row || !row.genLog) return '未知原因(无日志)'
      const lines = row.genLog.split('\n').map(l => l.trim()).filter(Boolean)
      const main = lines.filter(l => !l.startsWith('退出码') && !l.startsWith('[')).slice(0, 2)
      return main.length ? main.join(' ') : (lines[0] || '未知原因')
    },
    loadMyDatasets() {
      request.get("/generation/mylist").then(res => {
        if (res.code == '200') this.myDatasets = res.data || []
      })
    },
    downloadDs(row) {
      const u = localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {}
      window.open(`/api/generation/download?id=${row.id}&token=${u.token || ''}`)
    },
    handleAvatarSuccess(res){
      this.user.avatar = res.data
    },
    submit(){
      request.post("/user/updateUserInfo", this.user).then(res => {
        if (res.code == '200'){
          this.$message.success('保存成功');
          localStorage.setItem("user", JSON.stringify(res.data));
        } else {
          this.$message.error(res.msg);
        }
      })
    }
  }
}
</script>

<style scoped>
.person-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px 16px;
  gap: 18px;
}

.person-topbar {
  width: 100%;
  max-width: 960px;
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

.person-title {
  color: var(--navy);
  font-size: 18px;
  font-weight: 850;
}

.person-card {
  width: 100%;
  max-width: 960px;
}

.avatar-preview {
  width: 96px;
  height: 96px;
  border-radius: 50%;
  object-fit: cover;
  object-position: top; /* 竖版人像优先显示上半部分,避免脸部被居中裁切 */
  border: 2px solid rgba(34, 110, 232, .35);
  cursor: pointer;
}

.avatar-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--panel-soft);
  border: 2px dashed rgba(34, 110, 232, .3);
  color: var(--muted);
  font-size: 12px;
}
.myds-count {
  margin-left: 10px;
  font-size: 12px;
  color: #226ee8;
  background: rgba(34, 110, 232, .08);
  border: 1px solid rgba(34, 110, 232, .25);
  border-radius: 999px;
  padding: 2px 10px;
}
.myds-pager {
  display: flex;
  justify-content: center;
  margin-top: 12px;
}
.fail-brief {
  margin: 0 0 8px;
  font-size: 14px;
  font-weight: 700;
  color: #b3434c;
  line-height: 1.6;
}
.fail-tip {
  margin: 0 0 6px;
  font-size: 12px;
  color: #71859a;
}
.fail-log {
  max-height: 320px;
  overflow: auto;
  background: #0f1c2e;
  color: #cfe3ff;
  font-size: 12px;
  line-height: 1.7;
  border-radius: 8px;
  padding: 12px 14px;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>

<style>
/* 非scoped: el-table列类与挂载到body的tooltip气泡 */
.person-page .el-table .time-nw {
  white-space: nowrap;
}
</style>
