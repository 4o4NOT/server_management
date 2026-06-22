import os
import configparser
import logging
from pathlib import Path

from .config_crypto import (
    is_encrypted, encrypt_value, decrypt_value,
    get_sensitive_keys, get_sensitive_env_vars,
    _process_ini_file, _process_dotenv_file,
)

# 配置日志
logger = logging.getLogger(__name__)

# 构建配置文件路径（项目根目录下的config.ini）
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')
DOTENV_FILE = os.path.join(BASE_DIR, '.env')

# 解密值缓存 {(section_lower, key_lower): plaintext}
_decrypted_sensitive_cache = {}

# 默认配置
DEFAULT_CONFIG = {
    'database': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'server_management',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': '127.0.0.1',
        'PORT': '3306',
    },
    'dingtalk': {
        'WEBHOOK_URL': '',
        'APP_KEY': '',
        'APP_SECRET': '',
        'OTP_VERIFY_URL': 'https://oapi.dingtalk.com/topapi/v2/user/otp/verify',
        'ACCESS_TOKEN_URL': 'https://oapi.dingtalk.com/gettoken',
    },
    'security': {
        'SECRET_KEY': '',
        'DEBUG': 'False',
        'ALLOWED_HOSTS': '',
    },
    'jwt': {
        'ACCESS_TOKEN_LIFETIME_HOURS': '3',
        'REFRESH_TOKEN_LIFETIME_DAYS': '1',
    },
    'ssh': {
        'CONNECT_TIMEOUT': '10',
        'EXEC_TIMEOUT': '30',
    },
    'tasks': {
        'RUN_BACKGROUND_TASKS': 'True',
        'PASSWORD_CHECK_INTERVAL': '300',
        'PASSWORD_EXPIRE_DAYS': '90',
    },
    'otp': {
        'VALID_WINDOW': '2',
    },
    'permission': {
        'DURATION_OPTIONS': '0.5=0.5小时,1=1小时,2=2小时,4=4小时,8=8小时,12=12小时',
        'PASSWORD_DISPLAY_MODE': 'auto_copy',
    }
}

# 环境变量到配置项的映射
# 格式: 环境变量名 -> (section, key, 默认值)
ENV_MAPPING = {
    # 数据库
    'DB_ENGINE': ('database', 'ENGINE', DEFAULT_CONFIG['database']['ENGINE']),
    'DB_NAME': ('database', 'NAME', DEFAULT_CONFIG['database']['NAME']),
    'DB_USER': ('database', 'USER', DEFAULT_CONFIG['database']['USER']),
    'DB_PASSWORD': ('database', 'PASSWORD', DEFAULT_CONFIG['database']['PASSWORD']),
    'DB_HOST': ('database', 'HOST', DEFAULT_CONFIG['database']['HOST']),
    'DB_PORT': ('database', 'PORT', DEFAULT_CONFIG['database']['PORT']),
    # 钉钉
    'DINGTALK_WEBHOOK_URL': ('dingtalk', 'WEBHOOK_URL', DEFAULT_CONFIG['dingtalk']['WEBHOOK_URL']),
    'DINGTALK_APP_KEY': ('dingtalk', 'APP_KEY', DEFAULT_CONFIG['dingtalk']['APP_KEY']),
    'DINGTALK_APP_SECRET': ('dingtalk', 'APP_SECRET', DEFAULT_CONFIG['dingtalk']['APP_SECRET']),
    # 安全
    'DJANGO_SECRET_KEY': ('security', 'SECRET_KEY', DEFAULT_CONFIG['security']['SECRET_KEY']),
    'DJANGO_DEBUG': ('security', 'DEBUG', DEFAULT_CONFIG['security']['DEBUG']),
    # JWT
    'JWT_ACCESS_TOKEN_LIFETIME_HOURS': ('jwt', 'ACCESS_TOKEN_LIFETIME_HOURS', DEFAULT_CONFIG['jwt']['ACCESS_TOKEN_LIFETIME_HOURS']),
    'JWT_REFRESH_TOKEN_LIFETIME_DAYS': ('jwt', 'REFRESH_TOKEN_LIFETIME_DAYS', DEFAULT_CONFIG['jwt']['REFRESH_TOKEN_LIFETIME_DAYS']),
    # SSH
    'SSH_CONNECT_TIMEOUT': ('ssh', 'CONNECT_TIMEOUT', DEFAULT_CONFIG['ssh']['CONNECT_TIMEOUT']),
    'SSH_EXEC_TIMEOUT': ('ssh', 'EXEC_TIMEOUT', DEFAULT_CONFIG['ssh']['EXEC_TIMEOUT']),
    # 任务
    'RUN_BACKGROUND_TASKS': ('tasks', 'RUN_BACKGROUND_TASKS', DEFAULT_CONFIG['tasks']['RUN_BACKGROUND_TASKS']),
    'PASSWORD_CHECK_INTERVAL': ('tasks', 'PASSWORD_CHECK_INTERVAL', DEFAULT_CONFIG['tasks']['PASSWORD_CHECK_INTERVAL']),
    'PASSWORD_EXPIRE_DAYS': ('tasks', 'PASSWORD_EXPIRE_DAYS', DEFAULT_CONFIG['tasks']['PASSWORD_EXPIRE_DAYS']),
    # OTP
    'OTP_VALID_WINDOW': ('otp', 'VALID_WINDOW', DEFAULT_CONFIG['otp']['VALID_WINDOW']),
    # 权限
    'PERMISSION_DURATION_OPTIONS': ('permission', 'DURATION_OPTIONS', DEFAULT_CONFIG['permission']['DURATION_OPTIONS']),
    'PASSWORD_DISPLAY_MODE': ('permission', 'PASSWORD_DISPLAY_MODE', DEFAULT_CONFIG['permission']['PASSWORD_DISPLAY_MODE']),
}


def _get_config_value(section, key, fallback=None):
    """
    获取配置值，优先级：环境变量 > config.ini（自动解密） > 默认值

    环境变量查找策略：
    1. 先在 ENV_MAPPING 中查找对应的环境变量
    2. 如果找不到，尝试用 SECTION_KEY 格式（如 DATABASE_ENGINE）
    3. config.ini 中的敏感值会被透明解密
    """
    section_lower = section.lower()
    key_lower = key.lower()

    # 1. 尝试环境变量
    for env_name, (env_section, env_key, default_val) in ENV_MAPPING.items():
        if env_section == section and env_key.lower() == key_lower:
            env_value = os.environ.get(env_name)
            if env_value:
                logger.debug(f"使用环境变量 {env_name} 的值")
                return env_value

    # 2. 尝试 SECTION_KEY 格式的环境变量
    env_name = f"{section.upper()}_{key.upper()}"
    env_value = os.environ.get(env_name)
    if env_value:
        logger.debug(f"使用环境变量 {env_name} 的值")
        return env_value

    # 3. 查解密缓存（透明加密处理后的敏感值）
    cache_key = (section_lower, key_lower)
    if cache_key in _decrypted_sensitive_cache:
        return _decrypted_sensitive_cache[cache_key]

    # 4. 如果 config.ini 存在，从中读取（非敏感项或缓存未命中）
    if os.path.exists(CONFIG_FILE):
        config = configparser.RawConfigParser()
        config.read(CONFIG_FILE, encoding='utf-8')
        if config.has_section(section) and config.has_option(section, key):
            return config.get(section, key)

    # 5. 返回默认值
    return fallback


def create_default_config():
    """创建默认配置文件（不含敏感信息）"""
    config = configparser.RawConfigParser()

    # 只写入非敏感的默认配置项
    for section, values in DEFAULT_CONFIG.items():
        config[section] = {}
        for key, value in values.items():
            # 敏感项留空，强制通过环境变量配置
            if key in ('PASSWORD', 'SECRET_KEY', 'WEBHOOK_URL', 'APP_KEY', 'APP_SECRET'):
                config[section][key] = ''
            else:
                config[section][key] = value

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        config.write(f)

    logger.info(f"已创建默认配置文件: {CONFIG_FILE}")


def load_config():
    """加载配置文件"""
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"配置文件 {CONFIG_FILE} 不存在，正在创建默认配置文件...")
        create_default_config()
        logger.info("已创建默认配置文件，请编辑敏感信息或通过环境变量设置")
    else:
        logger.info(f"正在加载配置文件: {CONFIG_FILE}")

    # 使用 RawConfigParser 禁用插值功能
    config = configparser.RawConfigParser()
    config.read(CONFIG_FILE, encoding='utf-8')

    return config


def _init_config():
    """
    初始化配置：加载文件 + 透明加密/解密处理。

    1. 先处理 .env 文件（解密 → 注入环境变量）
    2. 再处理 config.ini（解密 → 缓存）
    3. 返回 RawConfigParser 给 Config 类使用
    """
    # --- .env 处理 ---
    if os.path.exists(DOTENV_FILE):
        dotenv_decrypted = _process_dotenv_file(DOTENV_FILE, get_sensitive_env_vars())
        # 将解密后的 .env 值注入 os.environ（仅当未通过外部环境变量设置时）
        for key, value in dotenv_decrypted.items():
            if key not in os.environ and value:
                os.environ[key] = value
                logger.debug(".env 解密值已注入环境变量: %s", key)

    # --- config.ini 处理 ---
    cfg = load_config()
    decrypted = _process_ini_file(CONFIG_FILE, get_sensitive_keys())
    _decrypted_sensitive_cache.update(decrypted)

    return cfg


# 加载配置
try:
    app_config = _init_config()
    logger.info("配置加载完成")
except Exception as e:
    logger.error(f"加载配置时发生错误: {e}")
    raise


class Config:
    """配置类，提供对配置项的访问。优先级：环境变量 > config.ini > 硬编码默认值"""

    # 数据库配置
    DATABASE_ENGINE = _get_config_value('database', 'ENGINE', DEFAULT_CONFIG['database']['ENGINE'])
    DATABASE_NAME = _get_config_value('database', 'NAME', DEFAULT_CONFIG['database']['NAME'])
    DATABASE_USER = _get_config_value('database', 'USER', DEFAULT_CONFIG['database']['USER'])
    DATABASE_PASSWORD = _get_config_value('database', 'PASSWORD', DEFAULT_CONFIG['database']['PASSWORD'])
    DATABASE_HOST = _get_config_value('database', 'HOST', DEFAULT_CONFIG['database']['HOST'])
    DATABASE_PORT = _get_config_value('database', 'PORT', DEFAULT_CONFIG['database']['PORT'])

    # 钉钉配置
    DINGTALK_WEBHOOK_URL = _get_config_value('dingtalk', 'WEBHOOK_URL', DEFAULT_CONFIG['dingtalk']['WEBHOOK_URL'])
    DINGTALK_APP_KEY = _get_config_value('dingtalk', 'APP_KEY', DEFAULT_CONFIG['dingtalk']['APP_KEY'])
    DINGTALK_APP_SECRET = _get_config_value('dingtalk', 'APP_SECRET', DEFAULT_CONFIG['dingtalk']['APP_SECRET'])
    DINGTALK_OTP_VERIFY_URL = _get_config_value('dingtalk', 'OTP_VERIFY_URL', DEFAULT_CONFIG['dingtalk']['OTP_VERIFY_URL'])
    DINGTALK_ACCESS_TOKEN_URL = _get_config_value('dingtalk', 'ACCESS_TOKEN_URL', DEFAULT_CONFIG['dingtalk']['ACCESS_TOKEN_URL'])

    # 安全配置
    SECRET_KEY = _get_config_value('security', 'SECRET_KEY', DEFAULT_CONFIG['security']['SECRET_KEY'])
    DEBUG = _get_config_value('security', 'DEBUG', DEFAULT_CONFIG['security']['DEBUG']) in ('True', 'true', '1', 'yes')

    ALLOWED_HOSTS_STR = _get_config_value('security', 'ALLOWED_HOSTS', DEFAULT_CONFIG['security']['ALLOWED_HOSTS'])
    ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STR.split(',') if host.strip()]

    # JWT配置
    _jwt_access = _get_config_value('jwt', 'ACCESS_TOKEN_LIFETIME_HOURS', DEFAULT_CONFIG['jwt']['ACCESS_TOKEN_LIFETIME_HOURS'])
    JWT_ACCESS_TOKEN_LIFETIME_HOURS = int(_jwt_access) if _jwt_access else 3
    _jwt_refresh = _get_config_value('jwt', 'REFRESH_TOKEN_LIFETIME_DAYS', DEFAULT_CONFIG['jwt']['REFRESH_TOKEN_LIFETIME_DAYS'])
    JWT_REFRESH_TOKEN_LIFETIME_DAYS = int(_jwt_refresh) if _jwt_refresh else 1

    # SSH配置
    _ssh_conn = _get_config_value('ssh', 'CONNECT_TIMEOUT', DEFAULT_CONFIG['ssh']['CONNECT_TIMEOUT'])
    SSH_CONNECT_TIMEOUT = int(_ssh_conn) if _ssh_conn else 10
    _ssh_exec = _get_config_value('ssh', 'EXEC_TIMEOUT', DEFAULT_CONFIG['ssh']['EXEC_TIMEOUT'])
    SSH_EXEC_TIMEOUT = int(_ssh_exec) if _ssh_exec else 30

    # 任务配置
    RUN_BACKGROUND_TASKS = _get_config_value('tasks', 'RUN_BACKGROUND_TASKS', DEFAULT_CONFIG['tasks']['RUN_BACKGROUND_TASKS']) in ('True', 'true', '1', 'yes')
    _pwd_interval = _get_config_value('tasks', 'PASSWORD_CHECK_INTERVAL', DEFAULT_CONFIG['tasks']['PASSWORD_CHECK_INTERVAL'])
    PASSWORD_CHECK_INTERVAL = int(_pwd_interval) if _pwd_interval else 300
    _pwd_expire = _get_config_value('tasks', 'PASSWORD_EXPIRE_DAYS', DEFAULT_CONFIG['tasks']['PASSWORD_EXPIRE_DAYS'])
    PASSWORD_EXPIRE_DAYS = int(_pwd_expire) if _pwd_expire else 90

    # OTP配置
    _otp_window = _get_config_value('otp', 'VALID_WINDOW', DEFAULT_CONFIG['otp']['VALID_WINDOW'])
    OTP_VALID_WINDOW = int(_otp_window) if _otp_window else 2

    # 权限申请配置
    PERMISSION_DURATION_OPTIONS = _get_config_value('permission', 'DURATION_OPTIONS',
                                                     DEFAULT_CONFIG['permission']['DURATION_OPTIONS'])
    PASSWORD_DISPLAY_MODE = _get_config_value('permission', 'PASSWORD_DISPLAY_MODE',
                                               DEFAULT_CONFIG['permission']['PASSWORD_DISPLAY_MODE'])

    @classmethod
    def get_duration_options(cls):
        """
        解析时长选项配置，返回选项列表
        格式: [(小时数, 显示名称), ...]
        """
        options = []
        try:
            option_pairs = cls.PERMISSION_DURATION_OPTIONS.split(',')
            for pair in option_pairs:
                if '=' in pair:
                    hours_str, display_name = pair.split('=', 1)
                    hours = float(hours_str)
                    options.append((hours, display_name.strip()))
        except Exception as e:
            logger.error(f"解析时长选项配置失败: {e}")
            options = [(0.5, '0.5小时'), (1, '1小时'), (2, '2小时')]
        return options

    @classmethod
    def log_config_summary(cls):
        """记录配置摘要信息"""
        logger.info("=== 配置摘要 ===")
        logger.info(f"数据库主机: {cls.DATABASE_HOST}")
        logger.info(f"数据库名称: {cls.DATABASE_NAME}")
        logger.info(f"调试模式: {cls.DEBUG}")
        # 脱敏显示
        wh = cls.DINGTALK_WEBHOOK_URL
        if wh:
            masked = wh[:40] + "..." if len(wh) > 40 else wh
            logger.info(f"钉钉Webhook URL: {masked}")
        else:
            logger.warning("钉钉Webhook URL: 未配置")
        logger.info(f"SSH连接超时: {cls.SSH_CONNECT_TIMEOUT}秒")
        logger.info(f"后台任务启用: {cls.RUN_BACKGROUND_TASKS}")
        logger.info(f"密码过期天数: {cls.PASSWORD_EXPIRE_DAYS}天")
        logger.info(f"OTP验证窗口期: {cls.OTP_VALID_WINDOW}")
        # 安全警告
        if not cls.SECRET_KEY:
            logger.critical("!!! SECRET_KEY 未配置，请通过环境变量 DJANGO_SECRET_KEY 设置 !!!")
        if not cls.DATABASE_PASSWORD:
            logger.warning("数据库密码未配置，请通过环境变量 DB_PASSWORD 设置")
        logger.info("=============== ")
