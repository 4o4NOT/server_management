import os
import logging
from pathlib import Path
from datetime import timedelta

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 确保config.py文件存在后再导入
try:
    from .config import Config
    Config.log_config_summary()  # 记录配置摘要
    logger.info("已成功从config.py加载配置")
except ImportError as e:
    logger.warning(f"无法从config.py加载配置: {e}")
    # 如果config.py不存在，使用默认配置
    class Config:
        # 数据库配置
        DATABASE_ENGINE = 'django.db.backends.mysql'
        DATABASE_NAME = 'server_management'
        DATABASE_USER = 'root'
        DATABASE_PASSWORD = '360365851'
        DATABASE_HOST = '10.199.0.54'
        DATABASE_PORT = '3306'
        
        # 安全配置
        SECRET_KEY = 'django-insecure-pb)_hr@)uz=o4_a&&%b28ru=(bb7$7!a8+)8u0$@*oopwj=uzx'
        DEBUG = True
        
        # JWT配置
        JWT_ACCESS_TOKEN_LIFETIME_HOURS = 3
        JWT_REFRESH_TOKEN_LIFETIME_DAYS = 1
        
        # SSH配置
        SSH_CONNECT_TIMEOUT = 10
        SSH_EXEC_TIMEOUT = 30
        
        # 任务配置
        RUN_BACKGROUND_TASKS = True
        PASSWORD_CHECK_INTERVAL = 300
        
        # 钉钉配置
        DINGTALK_WEBHOOK_URL = 'https://oapi.dingtalk.com/robot/send?access_token=0afe9334cdfe89d2fdcd1eb9e761cb11212883a9c40588b0bc6972bb50a5ec98'
        DINGTALK_APP_KEY = 'your_dingtalk_app_key'
        DINGTALK_APP_SECRET = 'your_dingtalk_app_secret'
        DINGTALK_OTP_VERIFY_URL = 'https://oapi.dingtalk.com/topapi/v2/user/otp/verify'
        DINGTALK_ACCESS_TOKEN_URL = 'https://oapi.dingtalk.com/gettoken'

# 项目基础配置
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = Config.SECRET_KEY
DEBUG = Config.DEBUG
ALLOWED_HOSTS = ['*']

logger.info(f"Django项目配置加载完成，DEBUG模式: {DEBUG}")

# 应用定义
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app01.apps.App01Config',
    'rest_framework',
    'rest_framework_simplejwt',
    'app01.tasks'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app01.middleware.JWTAuthenticationMiddleware',  # JWT认证中间件
    'app01.middleware.SecurityHeadersMiddleware',
]

ROOT_URLCONF = 'server_management.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'server_management.wsgi.application'

# 数据库配置
DATABASES = {
    'default': {
        'ENGINE': Config.DATABASE_ENGINE,
        'NAME': Config.DATABASE_NAME,
        'USER': Config.DATABASE_USER,
        'PASSWORD': Config.DATABASE_PASSWORD,
        'HOST': Config.DATABASE_HOST,
        'PORT': Config.DATABASE_PORT,
    }
}

# 密码验证
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# 国际化
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = False

# 静态文件
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'app01', 'static'),
]

# 默认主键字段
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 登录重定向
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'
LOGIN_URL = '/login/'

# 认证后端
AUTHENTICATION_BACKENDS = [
    'app01.views.CustomModelBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# 自定义用户模型
AUTH_USER_MODEL = 'app01.UserInfo'

# 日志配置
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    }
}

# JWT配置
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    )
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=Config.JWT_ACCESS_TOKEN_LIFETIME_HOURS),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=Config.JWT_REFRESH_TOKEN_LIFETIME_DAYS),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
    
    # 添加以下配置以更好地处理令牌过期
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(hours=Config.JWT_ACCESS_TOKEN_LIFETIME_HOURS),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=Config.JWT_REFRESH_TOKEN_LIFETIME_DAYS),
}

# 安全配置
SECURE_COOKIE = False  # 开发环境设置为False，生产环境设置为True
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# 钉钉OTP配置
DINGTALK_APP_KEY = Config.DINGTALK_APP_KEY
DINGTALK_APP_SECRET = Config.DINGTALK_APP_SECRET
DINGTALK_OTP_VERIFY_URL = Config.DINGTALK_OTP_VERIFY_URL
DINGTALK_ACCESS_TOKEN_URL = Config.DINGTALK_ACCESS_TOKEN_URL

# SSH连接超时设置
SSH_CONNECT_TIMEOUT = Config.SSH_CONNECT_TIMEOUT  # 秒
SSH_EXEC_TIMEOUT = Config.SSH_EXEC_TIMEOUT     # 秒

# 后台任务配置
RUN_BACKGROUND_TASKS = Config.RUN_BACKGROUND_TASKS  # 是否运行后台任务
PASSWORD_CHECK_INTERVAL = Config.PASSWORD_CHECK_INTERVAL  # 密码检查间隔（秒），默认5分钟