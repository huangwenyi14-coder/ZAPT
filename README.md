# 数字弈境 APT 数据集平台 · version2 部署包

在 version1 基础上新增:**在线数据生成系统**(首页"生成你想要的数据"→ 自动调用 EvidenceForge 引擎 → 个人中心查看进度并下载)。

## 〇、本包部署目标(已预配,可直接用)

本 version2 已按 **Linux 服务器 172.23.111.192** 预配好全部地址,三处均已写入:
- 数据库连接:`jdbc:mysql://172.23.111.192:3306`(jar 内已生效)
- 头像/文件下载地址:`http://172.23.111.192:{端口}`(jar 内已生效)
- 前端代理 target:`http://172.23.111.192:9999`(vue.config.js)
- uv 调用方式:按 PATH 查找(Linux)

### 服务器(Linux)部署命令

```bash
# 1. MySQL(服务器上):建库 + 授权(走IP连库,root@localhost 不够)
mysql -u root -p < sql/aptweb.sql
mysql -u root -p -e "CREATE USER IF NOT EXISTS 'root'@'172.23.111.192' IDENTIFIED BY '你的MySQL密码';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'172.23.111.192' WITH GRANT OPTION; FLUSH PRIVILEGES;"

# 2. 生成引擎依赖(uv 未装先装: curl -LsSf https://astral.sh/uv/install.sh | sh)
cd back/scripts/APTChain-Benchmark && uv sync && cd ../../..

# 3. 后端(在 back 目录下启动!)
cd back && nohup java -jar aptback-0.0.1-SNAPSHOT.jar > backend.log 2>&1 &

# 4. 前端(另开会话)
cd front && npm install && nohup npm run serve > front.log 2>&1 &
# 访问 http://172.23.111.192:8080 (admin/admin)

# 5. 防火墙放行(Ubuntu示例)
sudo ufw allow 8080/tcp && sudo ufw allow 9999/tcp && sudo ufw allow 3306/tcp
```

> 注意:yml 里的数据库密码仍是开发机的 "0731",服务器 MySQL 密码不同的话改 `back/src/main/resources/application.yml` 后需重新 `mvn package`(服务器上需 JDK17+Maven),或改用启动参数覆盖:`java -jar aptback-0.0.1-SNAPSHOT.jar --spring.datasource.password=实际密码`(推荐,免重打包)。

## 一、目录结构

```
version2/
├── back/                          后端(Spring Boot 3.5.7 / JDK 17)
│   ├── aptback-0.0.1-SNAPSHOT.jar     已构建 jar(含全部最新修复)
│   ├── pom.xml  src/                   源码
│   ├── scripts/
│   │   ├── APTChain-Benchmark/        数据生成引擎源码(17MB,含 Windows 兼容修复)
│   │   └── minimax-key.txt             MiniMax API 凭据(★敏感,勿外传/勿提交git)
│   └── files/                          运行期数据(必须与 jar 同目录层级)
│       ├── dataset-packages/           2 个可下载剧本包(蜻蜓25M/污水45M,内含 data+scenario+defense)
│       ├── defense/                    74 个剧本的防御告警分片 jsonl
│       ├── avatars/  generation-requests/  generations/   空目录,运行时自动写入
├── front/                         前端(Vue2 + Element UI)
├── sql/aptweb.sql                 数据库脚本(10表 + admin + 74剧本689步骤)
├── README.md  DATABASE.md
```

## 二、环境要求

| 软件 | 版本 | 必须 | 说明 |
|---|---|---|---|
| JDK | 17 | ✅ | 运行后端 |
| MySQL | 8.0 | ✅ | 数据库 |
| Node.js | ≥16(含 npm) | ✅ | 前端 |
| Maven | 3.9.x | 仅改代码重打包时 | |
| **uv** | 0.12+ | 仅用生成功能 | Python 包管理器,首次生成前需装(见 §5) |

安装 uv(任选其一):
```bash
# 方式A: pip 安装(任意 Python≥3.8 环境)
pip install uv
# 方式B: 官方安装脚本(Windows PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 三、快速启动(3 条命令)

```bash
# 1. 导数据库
mysql -u root -p < sql/aptweb.sql

# 2. 起后端(在 back 目录!files/ 和 scripts/ 都依赖工作目录)
cd back && java -jar aptback-0.0.1-SNAPSHOT.jar

# 3. 起前端(另开终端)
cd front && npm install && npm run serve
```

访问 http://localhost:8080,登录 **admin / admin**。

## 四、可定制配置一览(★重点)

所有"改完需重新打包"的:`cd back && mvn package -DskipTests`

### 配置文件原貌(back/src/main/resources/application.yml)

部署最常改的就这一个文件,完整内容如下,对照改即可:

```yaml
server:
  port: 9999                        # ① 后端端口

spring:
  servlet:
    multipart:
      max-file-size: 20MB           # 上传大小限制(报告/头像)
      max-request-size: 20MB
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://172.23.111.192:3306/aptweb?useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
                                     # ② 数据库地址与端口(本包已按部署服务器 172.23.111.192 预配;MySQL 与后端同机也可改回 localhost)
    username: root                  # ③ 数据库账号
    password: "0731"                # ④ 数据库密码!必须带双引号(0开头数字会被YAML按八进制解析)

# 数据生成引擎(EvidenceForge)配置
eforge:
  uv-path: uv                                        # ⑤ 本包按 Linux 服务器预配:走 PATH 查找;若 java 进程找不到 uv,改成绝对路径(如 /root/.local/bin/uv)
  home: scripts/APTChain-Benchmark                   # 引擎目录(相对 back/,一般不动)
  key-file: scripts/minimax-key.txt                  # ⑥ API 凭据文件(第一行 https 地址,第三行 sk- 密钥)
  model: ""                         # ⑦ 模型名,留空=MiniMax-M2.7
  base-url: ""                      # ⑧ API 基地址,留空=官方 api.minimaxi.com(需 Anthropic 兼容接口)
```

> ①~④ 是跑起来的硬前提;⑤~⑧ 只影响"生成数据"功能,不用该功能可不改。

| 配置项 | 位置 | 默认值 | 说明 |
|---|---|---|---|
| 后端端口 | back/src/main/resources/application.yml → server.port | 9999 | 改后同步前端代理 target |
| **数据库地址/端口/账号/密码** | 同上 → spring.datasource.url/username/password | localhost:3306 root "0731" | **密码必须带双引号**(0开头数字会被YAML按八进制解析,真实踩坑);数据库端口非3306改 url 里的 :3306 |
| **生成引擎 uv 路径** | 同上 → eforge.uv-path | D:/anaconda3/envs/eforge/Scripts/uv.exe | **换机器必改**!改成那台机器 uv.exe 的绝对路径 |
| 生成引擎主目录 | 同上 → eforge.home | scripts/APTChain-Benchmark | 一般不动 |
| **MiniMax 凭据文件** | 同上 → eforge.key-file;实体在 back/scripts/minimax-key.txt | scripts/minimax-key.txt | key 失效/更换时编辑该 txt(第一行 https 地址,第三行 sk- 开头密钥) |
| **生成用模型名** | 同上 → eforge.model | 空=MiniMax-M2.7 | 换模型改这里,如 MiniMax-M2.6 等 |
| **API 基地址** | 同上 → eforge.base-url | 空=api.minimaxi.com | 换 API 供应商/中转地址改这里(需 Anthropic 兼容接口);留空则读凭据文件首行或引擎默认 |
| **头像等文件下载地址** | back/.../controller/FileController.java 搜 localhost(2处) | http://localhost: | 跨机器部署必改为主机对外 IP(端口自动跟 server.port),否则头像裂图;改的是 Java 代码要重打包 |
| 前端代理目标 | front/vue.config.js → proxy '/api' target | http://localhost:9999 | 后端不在本机时改 |
| 前端对外端口 | 启动命令 `npm run serve -- --port 9000` 或 Nginx listen | 8080 | |
| 生成并发数 | back/.../service/GenerationService.java → newFixedThreadPool(2) | 2 | 同时最多 2 个生成进程,其余排队 |
| 生成超时 | 同上 → TIMEOUT_MINUTES | 30 分钟 | |

不用改的:request.js 的 baseURL('/api' 相对路径)、el-upload action、各 Controller 的 @CrossOrigin(全局 CorsConfig 已放行)。

### 三机部署示例(前端 49.23.42.10:9000 / 后端 34.25.24.32:10001 / MySQL 与后端同机:3303)

1. application.yml:port→10001;url→`jdbc:mysql://localhost:3303/aptweb...`
2. FileController 两处 localhost→34.25.24.32,重打包
3. eforge.uv-path→新机器 uv.exe 路径
4. vue.config.js target→http://34.25.24.32:10001;前端 `--port 9000` 或 Nginx `listen 9000` + `proxy_pass http://34.25.24.32:10001/`

## 五、数据生成功能首次使用(重要)

1. 确认已装 uv,并改好 application.yml 的 eforge.uv-path
2. 首次生成前预热依赖(也可直接提交,后端调用时会自动 sync,但首次较慢):
```bash
cd back/scripts/APTChain-Benchmark && uv sync
```
3. 首页 → "没有找到你想要的数据集?" 展开表单:填写攻击事件描述(建议按威胁报告摘要密度,含组织/手法/工具/阶段,太简短会被质量门拒绝)、可选上传 APT 报告 PDF(仅 PDF,流量/样本待开发)、提交
4. 个人中心 → 我的数据集:状态 生成中(5秒轮询)→ 已生成/生成失败(可"查看原因"),成功可"打包下载"zip
5. **每次生成约消耗 3 次 MiniMax API 调用**(长报告多几次);生成耗时约 3~6 分钟
6. 产物:`back/files/generations/{用户名}/{目录}/`(数据集)+ 同名 `.log`(完整引擎日志);库里 gen_log 只存末尾摘要

纯文字提示词若失败并提示"来源贴合质量门未通过/可物化行为覆盖率不足",说明描述太薄,补充攻击细节后重新提交即可。

## 六、生产部署(前端)

```bash
cd front && npm run build    # 产出 dist/
```
Nginx:
```nginx
server {
    listen 80;
    root /path/to/dist;
    location / { try_files $uri $uri/ /index.html; }
    location /api/ { proxy_pass http://127.0.0.1:9999/; }   # 结尾斜杠去掉 /api 前缀
}
```

## 七、常见问题

| 现象 | 解决 |
|---|---|
| 后端起不来 Access denied | application.yml 密码错/没加引号(八进制坑) |
| 提交生成一直"生成中"不结束 | 查 generations 目录旁 .log;多半 uv-path 不对(日志会有找不到 uv 的报错);确认 uv 已安装 |
| 生成失败:CRLF/content mismatch | 已在引擎内修复(emitters 6处 newline="");若换用原版引擎需重打该补丁 |
| 剧本"打包下载"404 | jar 不在 back 目录启动,或 dataset-packages 缺 tar.gz |
| 头像裂图 | FileController 的 localhost 未改对外 IP |
| 生成记录时间 +8 小时 | JDBC url 必须 serverTimezone=Asia/Shanghai(已内置) |
| npm install 慢 | `npm config set registry https://registry.npmmirror.com` |

## 八、内置数据与已知修改

- 74 剧本/689 步骤/104 TTP 统计、中文描述、2 个可下载包(内含 data+scenario+defense)
- 引擎相对原版仅 9 行改动(Windows 换行兼容):emitters/base.py、host_base.py、zeek_base.py、bash_history.py、utils/files.py 的 open() 增加 newline=""——Linux/Mac 行为不变
- 社区/申请/生成记录均为空表
