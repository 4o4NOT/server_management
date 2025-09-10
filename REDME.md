# 服务器权限管理系统
这是一个基于Django的服务器权限管理系统，用于管理和控制对服务器的访问权限。系统支持用户管理、服务器管理、权限申请和审批流程，根据用户申请的密码有效期自动重置申请的服务器用户密码，并集成了OTP双因素认证和钉钉通知功能。

## 功能特性
### 用户管理
+ 用户注册和登录
+ 管理员用户管理（增删改查）
+ 用户状态管理（启用/禁用）
+ 密码重置功能
+ OTP双因素认证支持

### 服务器管理
+ 服务器信息维护（主机地址、端口、用户名等）
+ 服务器密码加密存储
+ SSH连接测试
+ 服务器批量操作支持

### 权限申请流程
+ 单个服务器权限申请
+ 批量服务器权限申请
+ 申请原因和时长设置
+ 管理员审批流程
+ OTP验证码验证

### 安全特性
+ 用户密码哈希存储
+ 服务器密码加密存储
+ OTP双因素认证
+ 权限分级管理
+ 操作日志记录

### 通知系统
+ 钉钉机器人通知集成
+ 权限申请实时通知
+ OTP验证码自动发送

## 技术栈
+ **后端**: Python 3.x, Django 3.x+
+ **前端**: HTML, CSS, JavaScript, jQuery
+ **数据库**: MySQL/PostgreSQL/SQLite
+ **认证**: JWT, Django Auth, PyOTP
+ **通信**: SSH, HTTP/HTTPS
+ **通知**: 钉钉机器人API

## 安装部署
### 环境要求
+ Python 3.7+
+ Django 3.2+
+ 数据库 (MySQL/PostgreSQL/SQLite)

### 安装步骤
1. 克隆项目代码

```plain
bash

git clone <项目地址>
cd server_management
```

2. 创建虚拟环境并激活

```plain
bash

python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

3. 安装依赖

```plain
bash

pip install -r requirements.txt
```
4. 根据自身环境修改config.ini配置文件，如数据库信息，钉钉推送地址
5. 初始化数据库

```plain
bash

python manage.py makemigrations
python manage.py migrate
```

6. 启动服务

```plain
bash

python manage.py runserver
```

## 配置文件说明
系统使用 config.ini 配置文件来管理各种参数，包括数据库连接、钉钉集成、安全设置等。

### config.ini 配置示例
```plain
ini

# 服务器管理系统配置文件
# 该文件包含系统运行所需的各种配置参数，运维人员可以根据实际环境进行调整

[database]
# 数据库配置部分，用于配置系统所使用的MySQL数据库连接信息
# 数据库引擎，指定使用MySQL数据库
engine = django.db.backends.mysql
# 数据库名称
name = server_management
# 数据库用户名
user = root
# 数据库密码
password = your_password
# 数据库服务器地址
host = 127.0.0.1
# 数据库端口号
port = 3306

[dingtalk]
# 钉钉集成配置部分，用于配置与钉钉平台的集成参数
# 钉钉机器人Webhook地址，用于发送通知消息
webhook_url = https://oapi.dingtalk.com/robot/send?access_token=your_token

[security]
# 安全配置部分，包含系统安全相关设置
# Django密钥，用于加密签名，生产环境应替换为安全的随机字符串
secret_key = your_secret_key_here
# 调试模式开关
debug = False

[jwt]
# JWT令牌配置部分，用于配置JSON Web Token的相关参数
# 访问令牌有效期（小时）
access_token_lifetime_hours = 3
# 刷新令牌有效期（天）
refresh_token_lifetime_days = 1

[ssh]
# SSH连接配置部分，用于配置与服务器建立SSH连接的超时设置
# SSH连接超时时间（秒）
connect_timeout = 10
# SSH命令执行超时时间（秒）
exec_timeout = 30

[otp]
# OTP令牌配置部分，用于配置一次性密码相关参数
# OTP验证窗口期（默认为1，表示前后各1个时间段）
valid_window = 3

[permission]
# 权限申请配置部分，用于配置用户权限申请的相关参数
# 可申请的时长选项（单位：小时）
# 格式：选项值=显示名称
duration_options = 0.5=0.5小时,1=1小时,2=2小时,4=4小时
```

## 使用说明
### 初始设置
1. 注册用户
2. 修改数据库user_info表的is_superuser字段（0为普通用户，1为管理员）
3. 使用管理员账号登录系统
4. 进入用户管理页面创建普通用户
5. 进入服务器管理页面添加需要管理的服务器
6. 配置OTP双因素认证

### OTP双因素认证设置
1. 管理员登录后进入"OTP管理"页面
2. 使用手机OTP应用（如Google Authenticator）扫描二维码
3. 输入应用生成的验证码完成绑定

### 权限申请流程
1. 普通用户登录系统
2. 进入首页或批量申请页面
3. 选择需要申请权限的服务器
4. 填写申请原因和时长
5. 提交申请
6. 等待钉钉通知中的OTP验证码
7. 输入验证码完成验证
8. 获取临时密码访问服务器

### 管理员操作
1. 审批用户申请（人工发送验证给用户）
2. 管理服务器信息
3. 重置用户密码
4. 管理用户状态

## 安全说明
### 密码安全
+ 用户密码使用Django内置哈希算法存储，无法逆向解密
+ 服务器密码使用Fernet对称加密存储，可解密
+ 密码复杂度要求：至少8位，包含大小写字母、数字和特殊字符

### 访问控制
+ 系统采用基于角色的访问控制（RBAC）
+ 普通用户只能申请权限
+ 管理员用户拥有系统管理权限
+ 敏感操作需要OTP验证

### 数据保护
+ 敏感信息（如密码）在传输和存储过程中均加密
+ 数据库连接使用安全配置
+ API接口采用JWT令牌认证

## API接口
### 用户认证
+ `POST /login/` - 用户登录
+ `POST /register/` - 用户注册
+ `POST /logout/` - 用户登出

### 用户管理（需要管理员权限）
+ `GET /user_management/` - 用户管理页面
+ `POST /delete_user/<user_id>/` - 删除用户
+ `POST /toggle_user_active/<user_id>/` - 切换用户状态
+ `POST /reset_password/<user_id>/` - 重置用户密码

### 服务器管理（需要管理员权限）
+ `GET /server_management/` - 服务器管理页面
+ `POST /add_server/` - 添加服务器
+ `POST /update_server/<server_id>/` - 更新服务器
+ `POST /delete_server/<server_id>/` - 删除服务器

### 权限申请
+ `POST /apply_permission/` - 申请服务器权限
+ `POST /bulk_apply_permission/` - 批量申请服务器权限
+ `POST /verify_otp/` - 验证OTP并获取密码
+ `POST /verify_bulk_otp/` - 验证批量申请OTP

## 维护管理
### 定时任务
系统包含密码过期检查功能，建议设置定时任务定期执行：

```plain
bash

python manage.py shell -c "from app01.views import check_expired_passwords; check_expired_passwords()"
```

### 日志查看
系统日志记录在Django默认日志文件中，可以查看用户操作和系统异常。

### 备份策略
建议定期备份：

+ 数据库数据
+ Django配置文件
+ 用户上传的文件（如果有）

## 常见问题
### 忘记管理员密码
如果忘记管理员密码，可以通过以下方式重置：

1. 使用其他管理员账户登录重置密码
2. 通过Django shell命令重置
3. 重新创建超级用户

### OTP验证失败
如果OTP验证失败，请检查：

1. 手机时间和服务器时间是否同步
2. OTP应用是否正确绑定
3. 验证码是否在有效期内

### 服务器连接失败
如果服务器连接失败，请检查：

1. 服务器地址和端口是否正确
2. 用户名和密码是否正确
3. 网络连接是否正常
4. SSH服务是否正常运行

## 贡献指南
欢迎提交Issue和Pull Request来改进系统功能。



## 联系方式
bi6nyx@163.com

