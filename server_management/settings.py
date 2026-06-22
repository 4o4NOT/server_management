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
    Config.log_config_summary()
    logger.info("已成功从config.py加载配置")
except ImportError as e:
    logger.warning(f"无法从config.py加载配置: {e}")
    # 如果config.py不存在，使用默认配置
    class Config:
        DATABASE_ENGINE = 'django.db.backends.mysql'
        DATABASE_NAME = 'server_management'
        DATABASE_USER = 'root'
        DATABASE_PASSWORD = ''
        DATABASE_HOST = '127.0.0.1'
        DATABASE_PORT = '3306'
        SECRET_KEY = ''
        DEBUG = False
        JWT_ACCESS_TOKEN_LIFETIME_HOURS = 3
        JWT_REFRESH_TOKEN_LIFETIME_DAYS = 1
        SSH_CONNECT_TIMEOUT = 10
        SSH_EXEC_TIMEOUT = 30
        RUN_BACKGROUND_TASKS = True
        PASSWORD_CHECK_INTERVAL = 300
        PASSWORD_EXPIRE_DAYS = 90
        OTP_VALID_WINDOW = 2
        DINGTALK_WEBHOOK_URL = ''
        DINGTALK_APP_KEY = ''
        DINGTALK_APP_SECRET = ''
        DINGTALK_OTP_VERIFY_URL = 'https://oapi.dingtalk.com/topapi/v2/user/otp/verify'
        DINGTALK_ACCESS_TOKEN_URL = 'https://oapi.dingtalk.com/gettoken'
        PERMISSION_DURATION_OPTIONS = '0.5=0.5小时,1=1小时,2=2小时'
        PASSWORD_DISPLAY_MODE = 'auto_copy'
        ALLOWED_HOSTS = ['*']

# 项目基础配置
BASE_DIR = Path(__file__).resolve().parent.parent

# 安全配置 — SECRET_KEY 和 DEBUG 通过环境变量/config.ini注入
SECRET_KEY = Config.SECRET_KEY
DEBUG = Config.DEBUG
ALLOWED_HOSTS = Config.ALLOWED_HOSTS if Config.ALLOWED_HOSTS else ['*']

if not SECRET_KEY:
    logger.critical("!!! SECRET_KEY 未配置！请设置环境变量 DJANGO_SECRET_KEY !!!")
    # 开发环境用不安全密钥兜底
    if DEBUG:
        SECRET_KEY = 'django-insecure-dev-only-do-not-use-in-production'
        logger.warning("使用开发环境默认 SECRET_KEY")

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
    'django.middleware.csrf.CsrfViewMiddleware',    # 已启用 CSRF 保护
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app01.middleware.JWTAuthenticationMiddleware',
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
    'app01.views.auth.CustomModelBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# 自定义用户模型
AUTH_USER_MODEL = 'app01.UserInfo'

# 日志配置 — 同时输出到控制台和文件
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

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
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'server_management.log'),
            'maxBytes': 10 * 1024 * 1024,  # 10MB 轮转
            'backupCount': 30,              # 保留30个历史文件
            'formatter': 'verbose',
            'encoding': 'utf-8',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO' if not DEBUG else 'DEBUG',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'app01': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
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
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(hours=Config.JWT_ACCESS_TOKEN_LIFETIME_HOURS),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=Config.JWT_REFRESH_TOKEN_LIFETIME_DAYS),
}

# 安全配置
SECURE_COOKIE = False  # 内网环境设置为False，生产环境HTTPS设置为True
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
# CSRF信任的源（内网环境）
CSRF_TRUSTED_ORIGINS = []

# 缓存配置 — 使用本地内存缓存
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'server_management_cache',
    }
}

# 钉钉OTP配置
DINGTALK_APP_KEY = Config.DINGTALK_APP_KEY
DINGTALK_APP_SECRET = Config.DINGTALK_APP_SECRET
DINGTALK_OTP_VERIFY_URL = Config.DINGTALK_OTP_VERIFY_URL
DINGTALK_ACCESS_TOKEN_URL = Config.DINGTALK_ACCESS_TOKEN_URL

# SSH连接超时设置
SSH_CONNECT_TIMEOUT = Config.SSH_CONNECT_TIMEOUT
SSH_EXEC_TIMEOUT = Config.SSH_EXEC_TIMEOUT

# 后台任务配置
RUN_BACKGROUND_TASKS = Config.RUN_BACKGROUND_TASKS
PASSWORD_CHECK_INTERVAL = Config.PASSWORD_CHECK_INTERVAL
