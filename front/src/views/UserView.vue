<template >
  <div class="user" v-if="user.role=='管理员'">
    <div style="margin-bottom: 10px">
      <el-input v-model="userName" placeholder="请输入内容" style="width: 200px;margin-right: 10px"></el-input>
      <el-button type="warning" @click="load(true)" style="background-color: #f59e0b; border-color: #f59e0b;">查询</el-button>
      <el-button type="primary" @click="reset" style="background-color: #4a90e2; border-color: #4a90e2;">重置</el-button>
      <el-button type="success" @click="add" style="background-color: #10b981; border-color: #10b981;">新增</el-button>
    </div>
      <el-table :data="tableData" style="width: 100%;margin-bottom: 10px">
      <el-table-column prop="id" label="ID" width="180"></el-table-column>
      <el-table-column prop="userName" label="姓名" width="180"></el-table-column>
        <el-table-column prop="role" label="权限" width="180"></el-table-column>
        <el-table-column prop="avatar" label="头像">
          <template v-slot="scope">
            <el-image style="width: 80px; height: 80px;border-radius: 50%" :src="scope.row.avatar" :preview-src-list="[scope.row.avatar]"></el-image>
          </template>
        </el-table-column>
      <el-table-column  label="操作" width="280px">
        <template slot-scope="scope">
          <el-button type="success" @click="download(scope.row)" style="background-color: #10b981; border-color: #10b981;">下载头像</el-button>
          <el-button type="primary" @click="update(scope.row)" style="background-color: #4a90e2; border-color: #4a90e2;">编辑</el-button>
          <el-button type="danger" @click="del(scope.row.id)" style="background-color: #ef4444; border-color: #ef4444;">删除</el-button>
        </template>
      </el-table-column>
      </el-table>
    <div>
      <el-pagination
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
          :current-page="pageNum"
          :page-sizes="[2, 4, 10, 20]"
          :page-size="2"
          layout="total, sizes, prev, pager, next, jumper"
          :total="total">
      </el-pagination>
    </div>
    <el-dialog title="用户信息" :visible.sync="dialogVisible" width="30%">
      <el-form :model="form" label-width="80px">
        <el-form-item label="姓名">
          <el-input v-model="form.userName" placeholder="请输入姓名"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" placeholder="请输入密码"></el-input>
        </el-form-item>
        <el-form-item label="权限">
          <el-radio v-model="form.role" label="管理员" style="color: #2c3e50;"></el-radio>
          <el-radio v-model="form.role" label="用户" style="color: #2c3e50;"></el-radio>
        </el-form-item>
        <el-form-item label="头像">
          <el-upload
              action="/api/file/upload"
              :headers="{token: user.token}"
              :on-success="handleUploadSuccess">
            <el-button size="small" type="primary" style="background-color: #4a90e2; border-color: #4a90e2;">点击上传</el-button>
          </el-upload>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submit" style="background-color: #4a90e2; border-color: #4a90e2;">提交</el-button>
          <el-button @click="dialogVisible=false" style="background-color: #95a5a6; border-color: #95a5a6; color: white;">取消</el-button>
        </el-form-item>
      </el-form>
    </el-dialog>
  </div>
</template>
<script>
import request from "@/utils/request";
export default {
  data(){
    return{
      form:{
        userName:'',
        password:'',
        role:'',
        avatar:''
      },
      tableData:[],
      userName: '',
      pageNum:1,
      pageSize:2,
      total:0,
      user: localStorage.getItem("user") ? JSON.parse(localStorage.getItem("user")) : {},
      dialogVisible:false
    }
  },
  created() {
    this.load()
  },
  methods:{
    load(isResetPage = false){
      if (isResetPage) {
        this.pageNum = 1;
      } else {
        // 防止页码超出范围（如删数据后 total 变小）
        const maxPage = Math.max(1, Math.ceil(this.total / this.pageSize));
        if (this.pageNum > maxPage) {
          this.pageNum = maxPage;
        }
      }
      request.get('/user/selectPage',{
        params:{
          pageNum:this.pageNum,
          pageSize:this.pageSize,
          userName: this.userName
        }
      }).then(res=>{
        this.tableData=res.data.records
        this.total=res.data.total
      })
    },
    handleSizeChange(pageSize){
      this.pageSize=pageSize
      this.load()
    },
    handleCurrentChange(pageNum){
      this.pageNum=pageNum
      this.load()
    },
    del(id){
      request.delete('/user/delete',{params:{id:id}}).then(res=>{
        if(res.code=='200'){
          this.$message.success("删除成功")
          this.load()
        }else{
          this.$message.error(res.msg)
        }
      })
    },
    add(){
      this.dialogVisible=true
      this.form={}
    },
    update(row){
      this.dialogVisible=true
      this.form=JSON.parse(JSON.stringify(row))
    },
    handleUploadSuccess(res){
      this.form.avatar=res.data
    },
    submit(){
      request.post('/user',this.form).then(res=>{
        if(res.code=='200'){
          this.$message.success("操作成功")
          this.dialogVisible=false
          this.load()
        }else{
          this.$message.error(res.msg)
        }
      })
    },
    reset() {
      this.userName = '';
      this.load(true);
    },
    download(row) {
      window.open(row.avatar)
    }
  }
}
</script>