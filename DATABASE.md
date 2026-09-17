# 数据库表结构详解(aptweb)

数据库:MySQL 8.0,字符集 utf8mb4,共 **10 张表**,分四组:

```
用户与社区(6张)                    剧本数据集(2张)                申请类(2张)
┌──────────────┐                 ┌────────────────┐            ┌────────────────────────┐
│ user 用户     │──┐              │ playbook 剧本   │1───N       │ playbook_application   │
├──────────────┤  │              │  (74行)         │───┐        │  剧本下载申请           │
│ user_groups  │  │              ├────────────────┤   │        ├────────────────────────┤
│  小组         │  └──N group_members 成员(N:M)    │   │        │ generation_request     │
├──────────────┤                 │ playbook_step  │N  │        │  数据生成申请           │
│ topics 话题   │──N comments 评论│  攻击链步骤      │───┘        └────────────────────────┘
│      │       │                 │  (689行)        │
│      └─N likes 点赞            └────────────────┘
└──────────────┘
```

关系约定:关联靠逻辑外键(如 `playbook_step.playbook_id` → `playbook.id`),未建物理 FOREIGN KEY,MyBatis-Plus 在应用层维护。

---

## 一、用户与社区(6 张)

### 1. user —— 用户表

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 用户ID,主键 |
| user_name | varchar(255) | 否 | | 账号,唯一(应用层校验) |
| password | varchar(255) | 否 | | 密码(明文存储) |
| role | varchar(255) | 否 | | 角色:`管理员` / `用户`,注册默认"用户" |
| avatar | varchar(255) | 是 | | 头像URL,格式 `http://<后端>/file/download?fileName=avatars/<账号>.<ext>` |

- 本版本初始数据:仅 `admin`(id=16, admin/admin/管理员)。
- 接口序列化时 password 字段永不返回(`@JsonProperty(WRITE_ONLY)`)。
- 登录态用 JWT:token 以用户密码做 HMAC256 签名、24 小时过期,改密码即全端下线。

### 2. user_groups —— 小组表

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 小组ID |
| name | varchar(100) | 否 | | 小组名称 |
| description | text | 是 | | 小组描述 |
| avatar | varchar(255) | 是 | | 小组头像 |
| creator_id | int | 否 | | 创建者用户ID → user.id |
| created_at / updated_at | timestamp | 是 | CURRENT_TIMESTAMP | 创建/更新时间 |

- 删除权限:仅 creator_id 对应用户或管理员(后端校验)。

### 3. group_members —— 小组成员表(user 与 user_groups 的 N:M 关联)

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | bigint | 否 | 自增 | 主键 |
| group_id | int | 否 | | 小组ID → user_groups.id |
| user_id | int | 否 | | 用户ID → user.id |
| role | enum('moderator','member') | 是 | member | 组内角色 |
| created_at / updated_at | timestamp | 是 | CURRENT_TIMESTAMP | 时间戳 |

### 4. topics —— 话题表

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 话题ID |
| group_id | int | 否 | | 所属小组 → user_groups.id |
| author_id | int | 否 | | 作者 → user.id |
| title | varchar(200) | 否 | | 标题 |
| content | longtext | 是 | | 正文(富文本) |
| created_at / updated_at | timestamp | 是 | CURRENT_TIMESTAMP | 时间戳 |

- 删除权限:仅作者或管理员。like_count(点赞数)为运行时统计,不落库。

### 5. comments —— 评论表(支持楼中楼)

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 评论ID |
| topic_id | int | 否 | | 所属话题 → topics.id |
| author_id | int | 否 | | 作者 → user.id |
| content | longtext | 否 | | 评论内容 |
| parent_id | int | 是 | | 父评论ID(回复功能;NULL=顶级评论) |
| created_at / updated_at | timestamp | 是 | CURRENT_TIMESTAMP | 时间戳 |

### 6. likes —— 点赞表

| 列 | 类型 | 可空 | 说明 |
|---|---|---|---|
| id | int | 否 | 主键 |
| user_id | int | 否 | 点赞用户 → user.id |
| topic_id | int | 否 | 被点赞话题 → topics.id |

- 同一 (user_id, topic_id) 只应有一条,再次点赞=取消(删除该行)。

---

## 二、剧本数据集(2 张,本版本核心数据)

### 7. playbook —— 攻击链剧本主表(74 行)

一行为一个基于真实 APT 报告重建的攻击场景(如 `2016-11-17-apt23`),对应数据集页的一个卡片和详情页页头。

**标识与展示:**

| 列 | 类型 | 可空 | 说明 |
|---|---|---|---|
| id | int | 否 | 主键,详情页 URL 用它(`/playbook/:id`) |
| code | varchar(96) | 否 | 场景目录名(唯一键),格式 `YYYY-MM-DD-组织名` 或纯组织名,如 `2016-11-17-apt23`、`uat4356` |
| seq_no | int | 否 | 展示序号(剧本 #01~#74),**两个可下载的固定排 1、2** |
| attack_date | date | 是 | 攻击日期(从 code 前缀解析;32 个无日期前缀的为 NULL) |
| threat_group | varchar(96) | 否 | APT 组织英文代号,如 `lazarus`、`muddywater` |
| description | text | 是 | **中文描述**(51 条英文原文已人工翻译) |
| description_en | text | 是 | 英文原描述(仅存档,接口不返回) |
| source_report | varchar(512) | 是 | 来源 APT 报告文件名(57 个剧本有) |

**统计数据(导入时从数据集实际文件计算,冗余存储供列表页直查):**

| 列 | 类型 | 说明 |
|---|---|---|
| step_count | int | 攻击链步骤数(全表合计 689,平均 9.3) |
| event_count | int | 标注黑事件数(合计 1021) |
| red_herring_count | int | 诱饵干扰事件数 |
| host_count | int | 涉及主机数(如 WKS-ENG-021、WEB-01) |
| user_count | int | 场景内模拟用户数 |
| technique_count | int | 去重 ATT&CK 技术数(全库合计 104 个不同技术) |
| artifact_count | int | 攻击样本原件数(.eml 钓鱼邮件等) |
| file_count | int | 数据包内文件总数 |
| data_size_mb | int | 数据包解压后大小(MB),全库合计约 45GB |

**下载控制:**

| 列 | 类型 | 说明 |
|---|---|---|
| package_name | varchar(128) | 下载包文件名,如 `2014-06-30-dragonfly-energetic-bear.tar.gz`,对应 `back/files/dataset-packages/` 下的实体文件 |
| downloadable | tinyint | 1=开放直接下载(当前仅 2 个),0=需提交申请 |
| download_count | int | 累计下载次数(下载接口自增) |

**服务器路径与防御数据(version2 新增):**

| 列 | 类型 | 说明 |
|---|---|---|
| data_path | varchar(512) | 服务器数据目录绝对路径 `/mnt/raid0/.../quality-corpus-merged/{code}` |
| scenario_path | varchar(512) | 服务器场景目录路径 `.../quality-corpus-merged-scenarios/{code}` |
| defense_file | varchar(255) | 防御告警分片文件名 `{code}.jsonl`,实体在 `back/files/defense/`,74 行全部回填 |

**检索辅助(后加的两列):**

| 列 | 类型 | 说明 |
|---|---|---|
| technique_ids | varchar(600) | 该剧本全部 ATT&CK 技术号,逗号分隔,如 `T1566.001,T1204.002,T1547.001` |
| tactic_names | varchar(300) | 涉及战术中文名,逗号分隔,如 `初始访问,持久化,命令控制` |

### 8. playbook_step —— 攻击链步骤表(689 行)

一行 = 剧本的第 N 步,详情页「攻击链步骤」区块的数据源。

| 列 | 类型 | 可空 | 说明 |
|---|---|---|---|
| id | int | 否 | 主键 |
| playbook_id | int | 否 | 所属剧本 → playbook.id(索引 idx_pb: playbook_id+step_no) |
| step_no | int | 否 | 步骤序号,1 起 |
| storyline_id | varchar(96) | 是 | 源数据里的故事线ID,如 `rescue-2016-11-17-apt23-k-a-001`(溯源用) |
| actor | varchar(64) | 是 | 执行者(受害者账号),如 `priya.patel` |
| system | varchar(64) | 是 | 发生主机,如 `WKS-ENG-021`(MySQL 保留字,建表用了反引号) |
| activity | varchar(600) | 是 | 步骤动作描述(英文原文) |
| event_types | json | 是 | 该步产生的日志事件类型数组,如 `["email_message","file_create"]` |
| tactic_id | varchar(12) | 是 | ATT&CK 战术号(取该步首个有映射的技术),如 `TA0001` |
| tactic_name | varchar(24) | 是 | 战术中文名,如 `初始访问` |
| techniques | json | 是 | 该步全部 ATT&CK 技术(含名称),如 `["T1566.001 - Spearphishing Attachment"]` |

> 原有的 playbook_event(时间线黑事件,1021 行)表已按需删除;事件总数保留在 playbook.event_count 统计列里。时间线明细数据仍在下载包的 GROUND_TRUTH.json / RECORD_GROUND_TRUTH.jsonl 内。

---

## 三、申请类(2 张,初始为空)

### 9. playbook_application —— 剧本下载申请表

详情页对未开放剧本(downloadable=0)点「申请下载」提交表单后写入。

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 主键 |
| playbook_code | varchar(96) | 否 | | 申请的剧本 code → playbook.code(逻辑外键) |
| user_id | int | 是 | | 申请人 → user.id(后端以 token 身份写入,不可伪造) |
| user_name | varchar(64) | 是 | | 申请人姓名(表单填写) |
| email | varchar(128) | 是 | | 联系邮箱(审核结果回复用) |
| reason | varchar(500) | 是 | | 申请理由 |
| status | varchar(16) | 是 | 待审核 | 待审核 / 已通过 / 已拒绝 |
| created_at | datetime | 是 | CURRENT_TIMESTAMP | 提交时间 |

### 10. generation_request —— 数据生成申请表(version2:提交即自动触发生成)

- 上传的参考报告在 `back/files/generation-requests/`,命名 `{账号}_{时间戳}_{原名}.pdf`(仅 PDF)
- 无附件提交时,事件描述自动写成 TXT 作为生成输入
- 生成产物在 `back/files/generations/{账号}/{提示词前缀+时间戳-随机}/`,并发上限 2,超时 30 分钟

首页「没有找到你想要的数据集?点击这里生成你想要的数据」展开表单提交后写入。

| 列 | 类型 | 可空 | 默认 | 说明 |
|---|---|---|---|---|
| id | int | 否 | 自增 | 主键 |
| user_id | int | 是 | | 提交人 → user.id(token 身份) |
| user_name | varchar(64) | 是 | | 提交人账号(也是上传文件名前缀) |
| gen_events | text | 是 | | 要生成的事件描述(支持数千字长文) |
| source_file | varchar(255) | 是 | | 上传的参考报告文件名,**可选**;实体存 `back/files/generation-requests/`,命名 `{账号}_{时间戳}_{原文件名}.pdf`,目前仅收 PDF(流量/样本待开发) |
| remark | varchar(500) | 是 | | 备注(可选) |
| status | varchar(16) | 是 | 待处理 | 文字状态:生成中/已生成/生成失败(与 gen_status 同步) |
| gen_status | tinyint | 是 | 0 | **生成状态机:0=生成中 1=成功 2=失败** |
| output_path | varchar(512) | 是 | | 生成输出目录 `files/generations/{用户}/{目录}`(完整日志在同目录 .log 文件) |
| gen_log | varchar(1000) | 是 | | 引擎日志末尾摘要,失败原因所在;完整日志落盘 .log |
| created_at | datetime | 是 | CURRENT_TIMESTAMP | 提交时间(时区 Asia/Shanghai) |

---

## 四、数据量一览(本版本)

| 表 | 行数 | 说明 |
|---|---|---|
| user | 1 | 仅 admin |
| user_groups / group_members / topics / comments / likes | 0 | 空表待用 |
| playbook | 74 | 剧本主数据 |
| playbook_step | 689 | 平均 9.3 步/剧本,最短 5 最长 29 |
| playbook_application | 0 | 空表待用 |
| generation_request | 0 | 空表待用(提交后自动写入并触发引擎) |

## 五、管理小抄

```sql
-- 开放某个剧本的直接下载(先把 tar.gz 放进 back/files/dataset-packages/)
UPDATE playbook SET downloadable=1, package_name='<code>.tar.gz' WHERE code='<code>';

-- 查看待处理的数据生成申请
SELECT id,user_name,LEFT(gen_events,50) AS events,source_file,status,created_at
FROM generation_request WHERE status='待处理';

-- 查看剧本下载申请
SELECT * FROM playbook_application WHERE status='待审核';
```
