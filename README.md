# 服务器权限管理系统

基于 Django 的服务器权限管理系统，用于管理和控制对服务器的 SSH 访问权限。支持用户管理、服务器管理、权限申请和审批流程，根据用户申请的密码有效期自动重置服务器的用户密码，集成 OTP 双因素认证和钉钉通知。

---

## 目录

- [功能特性](#功能特性)
- [权限申请交互逻辑](#权限申请交互逻辑)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [配置说明](#配置说明)
- [Docker 部署（一线运维版）](#docker-部署一线运维版)
- [常规安装部署](#常规安装部署)
- [目标服务器 sudo 配置](#目标服务器-sudo-配置)
- [API 接口](#api-接口)
- [数据库表结构](#数据库表结构)
- [维护管理](#维护管理)
- [常见问题](#常见问题)

---

## 功能特性

### 用户管理
- 用户注册和登录（支持用户名 / 手机号双模式）
- 管理员用户管理（增删改查、批量删除）
- 用户状态管理（启用 / 禁用）
- 密码重置功能
- OTP 双因素认证

### 服务器管理
- 服务器信息维护（主机地址、端口、用户名等）
- 服务器密码 Fernet 加密存储（基于 PBKDF2 派生密钥）
- SSH 连接测试（添加时自动验证连通性）
- 服务器批量操作支持

### 权限申请流程
- 单个服务器权限申请
- 批量服务器权限申请
- 申请原因和时长设置（支持 0.5 ~ 12 小时）
- 操作类型区分（查看 / 修改，修改需关联运维单号）
- 管理员 OTP 审批流程（钉钉通知 + OTP 验证码）
- 密码自动复制或手动显示两种模式

### 安全特性
- 用户密码 Django 哈希存储（不可逆）
- 服务器密码 Fernet 对称加密存储（PBKDF2-HMAC-SHA256 密钥派生）
- OTP 双因素认证
- JWT + Cookie 双重认证
- CSRF 保护
- 配置文件透明加密（首次启动自动加密 config.ini / .env 敏感值）
- 配置文件机器绑定（加密密钥由 hostname + 项目路径派生，拷贝到其他机器不可解密）

### 通知系统
- 钉钉机器人 Webhook 通知
- 权限申请实时通知（含 OTP 验证码）

---

## 权限申请交互逻辑

### 单个权限申请流程

```
普通用户                           钉钉                      管理员
   │                                │                         │
   │ 1.选择服务器+账号+时长+原因     │                         │
   │─────────────────────────────────────────────────────────→│
   │                                │  2.钉钉推送申请通知      │
   │                                │    + OTP验证码           │
   │                                │                         │
   │ 3.用户在弹出框输入OTP验证码     │                         │
   │─────────────────────────────────────────────────────────→│
   │                                │    4.系统验证通过        │
   │                                │    5.SSH远程更新目标      │
   │                                │      服务器密码           │
   │←6.返回临时密码+到期倒计时       │                         │
   │                                │                         │
   │ 7.密码到期 → 后台定时任务       │                         │
   │   自动重置服务器密码            │                         │
```

### 多用户申请同一服务器的密码处理（最终策略）

当多个用户先后申请同一台服务器同一账户的权限时：

| 场景 | 行为 |
|---|---|
| **首次申请**（密码未过期） | 生成新随机密码 → SSH 更新目标服务器 → 返回到期时间 |
| **密码未过期，新时长 ≤ 剩余时间** | 共享当前密码，**不延长**过期时间，前端提示"您正在使用共享密码" |
| **密码未过期，新时长 > 剩余时间** | 共享当前密码，**自动延长**过期时间至新时长，SSH 不改密（密码不变） |
| **密码已过期** | 等同于首次申请：生成新密码 → SSH 改密 → 新过期时间 |

**设计原则**：
- 多人共享同一密码时，以"最长申请者"为准决定过期时间，保证不会有人在申请到密码后很快失效
- 密码不会因多个短时申请而导致后期申请者拿到的有效期缩水
- 前端会通过 confirm 弹窗或倒计时区域警告标签提示"共享密码"状态
- 刷新页面后倒计时和共享提示不会丢失（localStorage 持久化）

### 批量申请

- 用户一次性选择多台服务器 → 系统为所有服务器生成**统一临时密码**
- 所有服务器密码同步更新为同一密码，到期后统一重置
- 批量申请也需 OTP 验证

### 密码过期自动重置

后台线程每 300 秒（可配置）检查一次：

1. **权限到期**：到期时间已过的密码 → 生成新随机密码 → SSH 更新 → 清除过期标记
2. **长期未改**：超过 90 天（可配置）未修改的密码 → 自动更新

---

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.x, Django 3.x |
| 前端 | HTML5, CSS3, JavaScript, Bootstrap 5, Font Awesome 6 |
| 数据库 | MySQL（推荐）/ SQLite / PostgreSQL |
| 认证 | JWT (SimpleJWT) + Django Auth + PyOTP |
| 通信 | SSH (Paramiko), HTTP/HTTPS |
| 通知 | 钉钉机器人 Webhook API |
| 加密 | cryptography (Fernet + PBKDF2-HMAC-SHA256) |
| 部署 | Docker + Gunicorn（生产级 WSGI） |

---

## 项目结构

```
server_management/
├── app01/                          # 主应用
│   ├── views/                      # 视图（模块化拆分）
│   │   ├── __init__.py             #   统一重导出
│   │   ├── common.py               #   公共工具函数
│   │   ├── auth.py                 #   登录/注册/登出/改密/令牌
│   │   ├── server.py               #   服务器 CRUD / SSH
│   │   ├── permission.py           #   权限申请/OTP验证/密码过期
│   │   ├── batch.py                #   批量申请/批量获取密码
│   │   ├── otp.py                  #   OTP令牌管理
│   │   ├── user_mgmt.py            #   用户管理
│   │   ├── utils.py                #   服务器查询/过期查询
│   │   └── pages.py                #   首页/列表页/批量页/健康检查
│   ├── models.py                   #   数据模型
│   ├── middleware.py                #   JWT认证 + 安全头中间件
│   ├── backends.py                 #   自定义认证后端
│   ├── tasks/                      #   后台任务
│   │   ├── apps.py                 #     任务启动配置
│   │   └── tasks.py                #     密码过期检查线程
│   ├── management/commands/        #   管理命令
│   │   └── reset_passwords.py      #     手动密码重置命令
│   ├── templates/                  #   HTML模板
│   │   ├── base.html               #     基础骨架（所有页面继承）
│   │   ├── login.html              #     登录
│   │   ├── register.html           #     注册
│   │   ├── change_password.html    #     修改密码
│   │   ├── index.html              #     首页（权限申请入口）
│   │   ├── server_list.html        #     可申请服务器列表
│   │   ├── bulk_apply.html         #     批量申请
│   │   ├── server_management.html  #     服务器管理
│   │   ├── user_management.html    #     用户管理
│   │   ├── verify_token_page.html  #     令牌验证
│   │   └── footer.html             #     统一页脚
│   └── static/                     #   静态资源
│       ├── css/
│       │   └── custom.css          #     统一设计系统（所有页面共用）
│       └── js/
│           ├── custom.js           #     首页核心逻辑
│           ├── login.js            #     登录
│           ├── register.js         #     注册
│           ├── change_password.js  #     修改密码
│           ├── server_management.js#     服务器管理
│           └── user_management.js  #     用户管理
├── server_management/              # Django项目配置
│   ├── settings.py                 #   项目设置
│   ├── urls.py                     #   路由配置
│   ├── config.py                   #   配置加载（环境变量>config.ini>默认值）
│   └── config_crypto.py            #   配置文件透明加密模块
├── config.ini                      # 配置文件（首次启动自动加密敏感值）
├── .env.example                    # 环境变量模板
├── Dockerfile                      # Docker镜像构建
├── requirements.txt                # Python依赖
├── manage.py                       # Django管理脚本
└── logs/                           # 日志目录（自动创建）
```

---

## 配置说明

### 配置优先级

```
环境变量  >  .env文件  >  config.ini  >  程序默认值
```

程序**不会**在代码中硬编码任何密码或密钥（默认值均为空或安全占位符）。

### 配置文件透明加密

程序首次启动时会自动检测 `config.ini` 和 `.env` 中的敏感值，并将其替换为 `ENC:` 前缀的密文：

```ini
# 部署人员手写:
password = my_real_db_password

# 首次启动后自动变为:
password = ENC:gAAAAABmN3wXK7fY2...（密文）
```

**敏感字段包括**：
- 数据库密码
- 钉钉 Webhook URL、AppKey、AppSecret
- Django SECRET_KEY

**加密密钥来源**（优先级从高到低）：
1. 环境变量 `CONFIG_MASTER_KEY`（32 字节 URL-safe Base64）—— **推荐生产使用**
2. 机器指纹 `SHA256(hostname + 项目根路径)` —— **默认，配置绑定当前机器**

> **生成 CONFIG_MASTER_KEY**：在任意安装有 `cryptography` 的 Python 环境中执行：
> ```bash
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

### 配置方式一：环境变量（推荐生产环境）

所有敏感配置均支持通过环境变量注入：

| 环境变量 | 对应项 | 示例值 |
|---|---|---|
| `DB_ENGINE` | 数据库引擎 | `django.db.backends.mysql` |
| `DB_NAME` | 数据库名 | `server_management` |
| `DB_USER` | 数据库用户 | `root` |
| `DB_PASSWORD` | 数据库密码 | `your_password` |
| `DB_HOST` | 数据库地址 | `127.0.0.1` |
| `DB_PORT` | 数据库端口 | `3306` |
| `DJANGO_SECRET_KEY` | Django 密钥 | （随机字符串） |
| `DJANGO_DEBUG` | 调试模式 | `False` |
| `DINGTALK_WEBHOOK_URL` | 钉钉 Webhook | `https://oapi.dingtalk.com/robot/send?access_token=xxx` |
| `DINGTALK_APP_KEY` | 钉钉 AppKey | （可选） |
| `DINGTALK_APP_SECRET` | 钉钉 AppSecret | （可选） |
| `CONFIG_MASTER_KEY` | 配置加密主密钥 | （Fernet.generate_key() 生成） |
| `SSH_CONNECT_TIMEOUT` | SSH 连接超时(秒) | `10` |
| `SSH_EXEC_TIMEOUT` | SSH 命令超时(秒) | `30` |
| `RUN_BACKGROUND_TASKS` | 启用后台任务 | `True` |
| `PASSWORD_CHECK_INTERVAL` | 密码检查间隔(秒) | `300` |
| `PASSWORD_EXPIRE_DAYS` | 密码过期天数 | `90` |
| `OTP_VALID_WINDOW` | OTP 窗口期 | `2` |
| `PERMISSION_DURATION_OPTIONS` | 时长选项 | `0.5=0.5小时,1=1小时,2=2小时` |
| `PASSWORD_DISPLAY_MODE` | 密码显示模式 | `manual` 或 `auto_copy` |

### 配置方式二：.env 文件

将 `.env.example` 复制为 `.env`，填入真实值。`.env` 中的敏感值同样享受透明加密保护。

### 配置方式三：config.ini（兼容旧版）

直接编辑 `config.ini`，写入明文敏感值。首次启动时自动加密。

---

## Docker 部署（一线运维版）

> 以下步骤面向零 Docker 基础的运维人员，按顺序操作即可。

### 前置条件

- 一台 Linux 服务器（CentOS 7+ / Ubuntu 18.04+ / RHEL 7+）
- 服务器需要能访问 MySQL 数据库和钉钉 Webhook 地址
- 确保 Docker 已安装：

```bash
# 检查 Docker 是否安装
docker --version

# 如果未安装，CentOS 执行:
sudo yum install -y docker
sudo systemctl start docker
sudo systemctl enable docker

# 如果未安装，Ubuntu 执行:
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

### 第一步：准备数据库

确保 MySQL 数据库存在并创建好库（如果尚未创建）：

```sql
-- 在 MySQL 中执行
CREATE DATABASE IF NOT EXISTS server_management DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 第二步：准备配置文件

在服务器上创建工作目录，放入 `config.ini`（明文即可）：

```bash
mkdir -p /opt/server_management
cd /opt/server_management

# 创建配置文件
cat > config.ini << 'EOF'
[database]
engine = django.db.backends.mysql
name = server_management
user = root
password = 你的数据库密码
host = 你的数据库IP
port = 3306

[dingtalk]
webhook_url = https://oapi.dingtalk.com/robot/send?access_token=你的钉钉token
app_key =
app_secret =

[security]
secret_key = 随机生成一个长字符串
debug = False

[jwt]
access_token_lifetime_hours = 3
refresh_token_lifetime_days = 1

[ssh]
connect_timeout = 10
exec_timeout = 30

[tasks]
run_background_tasks = True
password_check_interval = 300
password_expire_days = 90

[otp]
valid_window = 3

[permission]
duration_options = 0.5=0.5小时,1=1小时,2=2小时,4=4小时,8=8小时,12=12小时
password_display_mode = auto_copy
EOF
```

> **关于 secret_key**：在 Linux 上执行 `openssl rand -base64 50` 生成一个随机字符串填入。

#### 生成配置加密主密钥（重要）

程序首次启动时会对 `config.ini` 中的敏感值（数据库密码、钉钉密钥、Django 密钥）自动加密。加密密钥默认由 **机器 hostname + 项目路径** 派生，Docker 容器的 hostname 每次重建都会变化，导致旧密文无法解密。

**必须手动指定固定主密钥**，避免容器重建后密钥失效。在任意装有 `cryptography` 的 Python 环境中生成：

```bash
# 方式一：宿主机已安装 Python + cryptography
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 方式二：用临时容器生成（无需安装 Python）
docker run --rm registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.5 \
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

输出类似 `zMF_qmVVFE0w_4nR_F6PqZlSqYKVzXnRNkYOuFqNlf8=`（44 字符 Base64），**妥善保管此密钥**。

### 第三步：加载镜像

运维将收到一个 Docker 镜像 tar 包（如 `server_management_v1.5.tar`）：

```bash
# 1. 将 tar 包上传到服务器的 /opt/server_management/ 目录
#    使用 scp / WinSCP / Xftp 等方式

# 2. 加载镜像
docker load -i /opt/server_management/server_management_v1.5.tar
# 看到输出 "Loaded image: registry.cn-hangzhou.aliyuncs.com/xxx/server-management:v1.5" 表示成功
```

### 第四步：启动容器

```bash
# 启动容器（首次部署）
# 注意：CONFIG_MASTER_KEY 必须与上面生成的一致，妥善保管
docker run -d \
  --name server_management \
  --restart=always \
  -p 8000:8000 \
  -e CONFIG_MASTER_KEY=zMF_qmVVFE0w_4nR_F6PqZlSqYKVzXnRNkYOuFqNlf8= \
  -v /opt/server_management/config.ini:/app/config.ini \
  -v /opt/server_management/logs:/app/logs \
  registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.5
```

参数说明：
| 参数 | 含义 |
|---|---|
| `-d` | 后台运行 |
| `--name server_management` | 容器名称 |
| `--restart=always` | 随系统自动重启 |
| `-p 8000:8000` | 宿主机 8000 端口映射到容器 8000 |
| `-e CONFIG_MASTER_KEY=...` | 配置加密主密钥（**必填**，与上面生成的值一致） |
| `-v .../config.ini:/app/config.ini` | 挂载配置文件 |
| `-v .../logs:/app/logs` | 挂载日志目录（持久化） |

### 第五步：初始化数据库

容器启动后需要执行数据库迁移：

```bash
# 执行数据库初始化
docker exec server_management python manage.py migrate
```

> 如果看到 `Applying app01.xxxx... OK` 的输出，表示数据库表创建成功。

### 第六步：验证部署

```bash
# 1. 检查容器状态
docker ps | grep server_management
# 应看到 STATUS 为 "Up X minutes"

# 2. 查看日志
docker logs server_management
# 应看到 "配置加载完成"、"已自动加密 config.ini 中的敏感值" 等日志

# 3. 访问系统
# 浏览器打开 http://服务器IP:8000
# 应看到登录页面

# 4. 检查 config.ini 是否已自动加密
cat /opt/server_management/config.ini | grep password
# 敏感值应已变为 ENC:... 格式

# 5. 确认密钥正确（不应出现解密失败警告）
docker logs server_management | grep -i "密钥\|解密\|encrypt"
# 应看到 "已自动加密 config.ini 中的敏感值" 或 "配置加载完成"
# 不应出现 "配置值解密失败" 或 "密钥不匹配"
```

### 更新镜像

拿到新版本 tar 包时：

```bash
# 1. 加载新镜像
docker load -i server_management_v1.6.tar

# 2. 停止并删除旧容器（config.ini 和日志在宿主机上不受影响）
docker stop server_management && docker rm server_management

# 3. 用新镜像重新启动（命令与第四步相同，改版本号）
# ⚠️ 必须携带相同的 CONFIG_MASTER_KEY，否则旧 config.ini 中的 ENC:... 密文无法解密！
docker run -d \
  --name server_management \
  --restart=always \
  -p 8000:8000 \
  -e CONFIG_MASTER_KEY=替换为之前生成并保管的主密钥 \
  -v /opt/server_management/config.ini:/app/config.ini \
  -v /opt/server_management/logs:/app/logs \
  registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.6
```

> **关于 CONFIG_MASTER_KEY**：每次更新镜像重建容器时，hostname 会变化，如果不带 `-e CONFIG_MASTER_KEY`，加密密钥将改变，导致 `config.ini` 中的 `ENC:...` 密文全部解密失败。表现为日志中出现 `"配置值解密失败：密钥不匹配"` 警告，数据库密码、钉钉密钥等敏感配置读取为密文而非明文，系统功能异常。**只要主密钥不变，无论重建多少次容器、迁移到哪台机器，密文都能正常解密。**

### 防火墙设置

如果服务器开启了防火墙，需要开放 8000 端口：

```bash
# firewalld (CentOS 7+)
sudo firewall-cmd --add-port=8000/tcp --permanent
sudo firewall-cmd --reload

# iptables
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
sudo service iptables save

# 云服务器请在安全组中放行 8000 端口
```

### Docker 部署常用运维命令

```bash
# 查看容器运行状态
docker ps -a | grep server_management

# 查看实时日志
docker logs -f server_management

# 查看最近 100 行日志
docker logs --tail 100 server_management

# 重启容器
docker restart server_management

# 进入容器调试
docker exec -it server_management bash

# 停止容器
docker stop server_management

# 删除容器（不影响数据和日志）
docker rm server_management
```

### 主机迁移指南

当需要将系统从一台服务器迁移到另一台时，关键是**确保加密密钥一致**，否则已加密的 `config.ini` 将无法解密。

#### 迁移前准备（在原主机上）

```bash
# 1. 备份数据库
mysqldump -h 数据库地址 -u root -p server_management > server_management_backup.sql

# 2. 备份配置文件（已加密，可直接拷贝）
cp /opt/server_management/config.ini /opt/server_management/config.ini.bak

# 3. 如果使用了 CONFIG_MASTER_KEY，记录它
#    检查之前 docker run 命令中 -e CONFIG_MASTER_KEY= 后面的值
#    或者检查宿主机环境变量：
echo $CONFIG_MASTER_KEY

# 4. 备份日志（可选）
cp -r /opt/server_management/logs /opt/server_management/logs.bak
```

#### 在新主机上恢复

```bash
# 1. 创建工作目录并放入备份文件
mkdir -p /opt/server_management
# 将 server_management_backup.sql、config.ini、镜像 tar 包上传到此目录

# 2. 恢复数据库
mysql -h 新数据库地址 -u root -p server_management < server_management_backup.sql

# 3. 修改 config.ini 中变化的部分（如数据库地址）
#    注意：不要修改已加密的 ENC:... 值
vim /opt/server_management/config.ini

# 4. 启动容器
#    ⚠️ 关键：必须使用与原主机相同的 CONFIG_MASTER_KEY
docker load -i server_management_v1.5.tar
docker run -d \
  --name server_management \
  --restart=always \
  -p 8000:8000 \
  -e CONFIG_MASTER_KEY=原主机的密钥值 \
  -v /opt/server_management/config.ini:/app/config.ini \
  -v /opt/server_management/logs:/app/logs \
  registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.5

# 5. 执行数据库迁移
docker exec server_management python manage.py migrate

# 6. 验证
docker logs server_management | grep -E "配置|密钥|加密"
# 应输出 "配置加载完成"，不应出现 "解密失败" 或 "密钥不匹配"
```

#### 如果没有使用 CONFIG_MASTER_KEY（仅依赖机器指纹）

原主机上 `config.ini` 是用 `SHA256(原hostname + 原路径)` 加密的，拷贝到新主机后密钥自然不匹配。此时有两个选择：

1. **推荐**：在原主机上先设置 `CONFIG_MASTER_KEY`，重新启动一次（已加密值不会重新加密，但解密缓存会更新），然后按上述流程迁移。
2. **应急**：在新主机上删除 `config.ini`，用明文重新创建 → 启动 → 自动加密。但需要重新填写所有敏感值。

---

## 常规安装部署

### 环境要求

- Python 3.7+
- MySQL 5.7+（或其他 Django 支持的数据库）
- Linux / Windows

### 安装步骤

**1. 克隆项目**

```bash
git clone <项目地址>
cd server_management
```

**2. 安装依赖**

```bash
pip install -r requirements.txt
```

**3. 配置**

```bash
# 方式A：复制环境变量模板
cp .env.example .env
vim .env     # 填入真实值

# 方式B：直接编辑 config.ini（敏感值首次启动自动加密）
vim config.ini
```

**4. 初始化数据库**

```bash
python manage.py makemigrations
python manage.py migrate
```

**5. 启动服务**

```bash
# 开发环境
python manage.py runserver

# 生产环境（需要先 pip install gunicorn）
gunicorn server_management.wsgi:application --bind 0.0.0.0:8000 --workers 4
```

---

## 目标服务器 sudo 配置

程序通过 SSH 执行 `chpasswd` 命令修改目标服务器用户密码，需要在**每台被管理的服务器**上配置 sudo 免密：

```bash
# 使用 visudo 编辑
sudo visudo

# 添加以下行（将 your_ssh_username 替换为实际用户名）
your_ssh_username ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd
```

> **为什么需要 sudo？** `chpasswd` 命令需要 root 权限才能修改任意用户的密码。如果不配置 sudo，SSH 用户执行 `chpasswd` 会权限不足导致改密失败。

---

## 初始设置

1. 注册一个用户
2. 在数据库中将其设为管理员：
   ```sql
   UPDATE user_info SET is_superuser = 1 WHERE user_name = '你的用户名';
   ```
3. 用管理员账号登录，进入「用户管理」→「令牌管理」绑定 OTP
4. 用手机 OTP 应用（Google Authenticator / 微软 Authenticator）扫描二维码
5. 进入「服务器管理」添加需要管理的服务器
6. 普通用户即可开始申请权限

---

## API 接口

### 用户认证

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/login/` | 用户登录 |
| `POST` | `/register/` | 用户注册 |
| `POST` | `/logout/` | 用户登出 |
| `POST` | `/change_password/` | 修改密码 |
| `POST` | `/api/refresh-token/` | 刷新 JWT 令牌 |

### 权限申请（普通用户）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/apply-permission/` | 单个权限申请 → 返回 OTP 验证提示 |
| `POST` | `/api/verify-otp/` | OTP 验证 → 返回服务器密码 |
| `POST` | `/api/bulk-apply-permission/` | 批量权限申请 |
| `POST` | `/api/verify-bulk-otp/` | 批量 OTP 验证 |
| `GET` | `/api/available_servers/` | 获取可申请的服务器列表 |
| `GET` | `/check_server_password_expiration/` | 查询密码过期时间 |

### 服务器管理（管理员）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/add_server/` | 添加服务器 |
| `POST` | `/api/update_server/<id>/` | 更新服务器 |
| `POST` | `/api/delete_server/<id>/` | 删除服务器 |
| `POST` | `/api/decrypt_server_password/<id>/` | 解密服务器密码（需 OTP） |

### 用户管理（管理员）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/delete_user/<id>/` | 删除用户 |
| `POST` | `/toggle_user_active/<id>/` | 切换用户状态 |
| `POST` | `/reset_password/<id>/` | 重置用户密码 |
| `POST` | `/bulk_delete_users/` | 批量删除用户 |

### 批量获取密码（供运维脚本使用）

```bash
# 登录获取 Cookie
curl -X POST http://localhost:8000/login/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=用户名" \
  -d "password=密码" \
  -c cookies.txt

# 批量获取服务器密码
curl -X POST http://localhost:8000/api/batch-passwords/ \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "hosts": ["10.199.0.52", "10.199.0.53"],
    "username": "root",
    "reason": "批量测试",
    "token_code": "070328"
  }'
```

### 健康检查

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health/` | 返回数据库状态、调试模式、OTP 状态 |

---

## 数据库表结构

### user_info（用户信息）

| 字段 | 类型 | 说明 |
|---|---|---|
| id | Integer | 主键 |
| user_name | Char(20) | 用户名，唯一 |
| phone | Char(11) | 手机号，唯一 |
| password | Char(128) | Django 哈希密码 |
| is_superuser | Boolean | 是否管理员 |
| is_active | Boolean | 是否激活 |
| last_login | DateTime | 最后登录时间 |
| date_joined | DateTime | 注册时间 |
| otp_secret | Char(32) | OTP 密钥 |
| otp_active | Boolean | OTP 是否已激活绑定 |

### server_info（服务器信息）

| 字段 | 类型 | 说明 |
|---|---|---|
| id | Integer | 主键 |
| host | Char(100) | 主机地址 |
| port | Integer | SSH 端口，默认 22 |
| username | Char(50) | 登录用户名 |
| password | Char(255) | Fernet 加密的密码 |
| description | Text | 描述信息 |
| last_password_change | DateTime | 最后修改时间 |
| current_duration | Integer | 当前密码有效期（小时） |
| generated_password | Char(128) | 批量申请的临时密码 |
| password_expiration_time | DateTime | 密码过期时间 |
| password_change_type | Char(20) | 修改类型（manual/auto_expired/permission_apply） |

**唯一约束**：`(host, username)` 组合唯一。

### permission_application（权限申请记录）

| 字段 | 类型 | 说明 |
|---|---|---|
| id | Integer | 主键 |
| applicant_id | FK→user_info | 申请人 |
| server_id | FK→server_info | 目标服务器 |
| account_name | Char(50) | 申请访问的账户名 |
| reason | Text | 申请原因 |
| duration | Integer | 申请时长（小时，支持小数） |
| status | Char(30) | 状态（pending/verification_pending/approved/rejected/expired/verification_failed） |
| operation_type | Char(10) | 操作类型（view=查看 / modify=修改 / batch=批量） |
| maintenance_ticket | Char(50) | 运维单号（修改操作时必填） |
| applied_at | DateTime | 申请时间 |
| approved_at | DateTime | 批准时间 |
| expired_at | DateTime | 过期时间 |
| verification_attempts | Integer | OTP 验证尝试次数 |
| last_verification_attempt | DateTime | 最后验证时间 |
| verification_code_sent | Boolean | 验证码是否已发送 |
| verification_code_sent_at | DateTime | 验证码发送时间 |
| batch_hosts | Text | 批量申请主机列表（JSON） |

---

## 维护管理

### 日志查看

日志同时输出到控制台和文件，文件位于 `logs/server_management.log`。日志采用 RotatingFileHandler：单文件最大 10MB，保留最近 30 个历史文件。

Docker 环境查看日志：
```bash
# 实时日志
docker logs -f server_management

# 持久化文件日志（挂载到了宿主机）
tail -f /opt/server_management/logs/server_management.log
```

### 健康检查

```bash
curl http://localhost:8000/health/
# 返回: {"status":"ok","database":"ok","debug":false,"otp_active":true,...}
```

### 备份策略

建议定期备份：
- 数据库数据（mysqldump）
- `config.ini` 配置文件（已加密，可安全备份）
- `logs/` 日志目录

---

## 常见问题

### 忘记管理员密码

1. 使用其他管理员账户登录重置密码
2. 通过 Django shell 命令重置：
   ```bash
   docker exec -it server_management python manage.py shell -c "
   from app01.models import UserInfo
   u = UserInfo.objects.get(user_name='管理员用户名')
   u.set_password('新密码')
   u.save()
   print('密码已重置')
   "
   ```

### OTP 验证失败

1. 检查手机时间和服务器时间是否同步
2. OTP 应用是否正确绑定
3. 验证码是否在有效期内
4. 确认系统已激活 OTP 令牌（「令牌管理」→ 扫码 → 输入验证码 → 激活）

### 服务器 SSH 连接失败

1. 检查服务器地址和端口是否正确
2. 检查用户名和密码是否正确（可直接 SSH 测试）
3. 确认目标服务器已配置 sudo 免密（见上文）
4. 检查网络连通性和防火墙

### 配置文件加密后无法解密

**现象**：
- 日志中出现 `"配置值解密失败：密钥不匹配（可能配置文件来自其他机器）"` 警告
- 数据库连接失败（密码读取为密文而非明文）
- 钉钉通知不发送（Webhook URL 解密失败）
- Django SECRET_KEY 无效导致会话/JWT 校验失败

**原因**：加密密钥默认由 `hostname + 项目路径` 派生。以下场景会导致密钥变化：

| 场景 | 密钥变化原因 |
|---|---|
| Docker 容器重建（`docker rm && docker run`） | 容器 hostname 变为新随机 ID |
| `config.ini` 拷贝到另一台机器 | 新机器 hostname + 路径不同 |
| 项目目录重命名或移动 | 项目路径变化 |
| 宿主机 hostname 变更 | 主机名改变 |

> **注意**：`docker restart` 不会改变 hostname，不会导致密钥失效。只有 `docker rm` 后重新 `docker run` 才会。

**解决方案**（任选一种）：

1. **设置 CONFIG_MASTER_KEY（推荐）**：在 `docker run` 时通过 `-e CONFIG_MASTER_KEY=密钥值` 传入固定的 32 字节 Base64 密钥。只要主密钥不变，无论迁移到哪台机器、重建多少次容器，密文都能正常解密。

2. **如果密钥已丢失**：删除 `config.ini`，用明文重新创建并填写敏感值，下次启动时自动重新加密。

3. **排查当前密钥**：进入容器查看派生的密钥：
   ```bash
   docker exec server_management python -c "
   import socket, hashlib, base64
   from pathlib import Path
   machine_id = socket.gethostname()
   project_root = str(Path('/app').resolve())
   fingerprint = hashlib.sha256((machine_id + project_root).encode()).digest()
   print('hostname:', machine_id)
   print('derived key:', base64.urlsafe_b64encode(fingerprint).decode())
   "
   ```

### Docker 容器启动失败

```bash
# 查看详细日志
docker logs server_management

# 常见原因：
# 1. config.ini 未挂载或路径错误 → 检查 -v 参数
# 2. 数据库连接失败 → 检查 config.ini 中的数据库配置
# 3. 端口冲突 → 改 -p 参数，如 -p 8001:8000
```
