import os
import configparser
import logging
from pathlib import Path

# 配置日志
logger = logging.getLogger(__name__)

# 构建配置文件路径（项目根目录下的config.ini）
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')

# 默认配置
DEFAULT_CONFIG = {
    'database': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'server_management',
        'USER': 'root',
        'PASSWORD': '360365851',
        'HOST': '10.199.0.54',
        'PORT': '3306',
    },
    'dingtalk': {
        'WEBHOOK_URL': 'https://oapi.dingtalk.com/robot/send?access_token=0afe9334cdfe89d2fdcd1eb9e761cb11212883a9c40588b0bc6972bb50a5ec98',
        'APP_KEY': 'your_dingtalk_app_key',
        'APP_SECRET': 'your_dingtalk_app_secret',
        'OTP_VERIFY_URL': 'https://oapi.dingtalk.com/topapi/v2/user/otp/verify',
        'ACCESS_TOKEN_URL': 'https://oapi.dingtalk.com/gettoken',
    },
    'security': {
        'SECRET_KEY': 'django-insecure-pb)_hr@)uz=o4_a&&%b28ru=(bb7$7!a8+)8u0$@*oopwj=uzx',
        'DEBUG': 'True',
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
    },
    'otp': {
        'VALID_WINDOW': '2',
    },
    'permission': {
        'DURATION_OPTIONS': '0.5=0.5小时,1=1小时,2=2小时,4=4小时,8=8小时,12=12小时',
    }
}

def create_default_config():
    """创建默认配置文件"""
    # 使用 RawConfigParser 禁用插值功能
    config = configparser.RawConfigParser()
    
    # 添加默认配置
    for section, values in DEFAULT_CONFIG.items():
        config[section] = values
    
    # 写入配置文件
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        config.write(f)
    
    logger.info(f"已创建默认配置文件: {CONFIG_FILE}")

def load_config():
    """加载配置文件"""
    # 如果配置文件不存在，创建默认配置文件
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"配置文件 {CONFIG_FILE} 不存在，正在创建默认配置文件...")
        create_default_config()
        logger.info("已创建默认配置文件")
    else:
        logger.info(f"正在加载配置文件: {CONFIG_FILE}")
    
    # 使用 RawConfigParser 禁用插值功能
    config = configparser.RawConfigParser()
    config.read(CONFIG_FILE, encoding='utf-8')
    
    # 验证配置文件是否包含所有必需的部分
    missing_sections = []
    for section in DEFAULT_CONFIG.keys():
        if not config.has_section(section):
            missing_sections.append(section)
    
    if missing_sections:
        logger.warning(f"配置文件缺少以下部分: {missing_sections}，将使用默认值")
    
    return config

# 加载配置
try:
    app_config = load_config()
    logger.info("配置加载完成")
except Exception as e:
    logger.error(f"加载配置时发生错误: {e}")
    raise

class Config:
    """配置类，提供对配置项的访问"""
    
    # 数据库配置
    DATABASE_ENGINE = app_config.get('database', 'ENGINE', fallback=DEFAULT_CONFIG['database']['ENGINE'])
    DATABASE_NAME = app_config.get('database', 'NAME', fallback=DEFAULT_CONFIG['database']['NAME'])
    DATABASE_USER = app_config.get('database', 'USER', fallback=DEFAULT_CONFIG['database']['USER'])
    DATABASE_PASSWORD = app_config.get('database', 'PASSWORD', fallback=DEFAULT_CONFIG['database']['PASSWORD'])
    DATABASE_HOST = app_config.get('database', 'HOST', fallback=DEFAULT_CONFIG['database']['HOST'])
    DATABASE_PORT = app_config.get('database', 'PORT', fallback=DEFAULT_CONFIG['database']['PORT'])
    
    # 钉钉配置
    DINGTALK_WEBHOOK_URL = app_config.get('dingtalk', 'WEBHOOK_URL', fallback=DEFAULT_CONFIG['dingtalk']['WEBHOOK_URL'])
    DINGTALK_APP_KEY = app_config.get('dingtalk', 'APP_KEY', fallback=DEFAULT_CONFIG['dingtalk']['APP_KEY'])
    DINGTALK_APP_SECRET = app_config.get('dingtalk', 'APP_SECRET', fallback=DEFAULT_CONFIG['dingtalk']['APP_SECRET'])
    DINGTALK_OTP_VERIFY_URL = app_config.get('dingtalk', 'OTP_VERIFY_URL', fallback=DEFAULT_CONFIG['dingtalk']['OTP_VERIFY_URL'])
    DINGTALK_ACCESS_TOKEN_URL = app_config.get('dingtalk', 'ACCESS_TOKEN_URL', fallback=DEFAULT_CONFIG['dingtalk']['ACCESS_TOKEN_URL'])
    
    # 安全配置
    SECRET_KEY = app_config.get('security', 'SECRET_KEY', fallback=DEFAULT_CONFIG['security']['SECRET_KEY'])
    DEBUG = app_config.getboolean('security', 'DEBUG', fallback=DEFAULT_CONFIG['security']['DEBUG'] == 'True')
    ALLOWED_HOSTS_STR = app_config.get('security', 'ALLOWED_HOSTS', fallback=DEFAULT_CONFIG['security']['ALLOWED_HOSTS'])
    ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STR.split(',') if host.strip()]
    
    # JWT配置
    JWT_ACCESS_TOKEN_LIFETIME_HOURS = app_config.getint('jwt', 'ACCESS_TOKEN_LIFETIME_HOURS', fallback=int(DEFAULT_CONFIG['jwt']['ACCESS_TOKEN_LIFETIME_HOURS']))
    JWT_REFRESH_TOKEN_LIFETIME_DAYS = app_config.getint('jwt', 'REFRESH_TOKEN_LIFETIME_DAYS', fallback=int(DEFAULT_CONFIG['jwt']['REFRESH_TOKEN_LIFETIME_DAYS']))
    
    # SSH配置
    SSH_CONNECT_TIMEOUT = app_config.getint('ssh', 'CONNECT_TIMEOUT', fallback=int(DEFAULT_CONFIG['ssh']['CONNECT_TIMEOUT']))
    SSH_EXEC_TIMEOUT = app_config.getint('ssh', 'EXEC_TIMEOUT', fallback=int(DEFAULT_CONFIG['ssh']['EXEC_TIMEOUT']))
    
    # 任务配置
    RUN_BACKGROUND_TASKS = app_config.getboolean('tasks', 'RUN_BACKGROUND_TASKS', fallback=DEFAULT_CONFIG['tasks']['RUN_BACKGROUND_TASKS'] == 'True')
    PASSWORD_CHECK_INTERVAL = app_config.getint('tasks', 'PASSWORD_CHECK_INTERVAL', fallback=int(DEFAULT_CONFIG['tasks']['PASSWORD_CHECK_INTERVAL']))

    # OTP配置
    OTP_VALID_WINDOW = app_config.getint('otp', 'VALID_WINDOW', fallback=int(DEFAULT_CONFIG['otp']['VALID_WINDOW']))
    
    # 权限申请配置
    PERMISSION_DURATION_OPTIONS = app_config.get('permission', 'DURATION_OPTIONS', fallback=DEFAULT_CONFIG['permission']['DURATION_OPTIONS'])
    PASSWORD_DISPLAY_MODE = app_config.get('permission', 'password_display_mode', fallback='auto_copy')

    @classmethod
    def get_duration_options(cls):
        """
        解析时长选项配置，返回选项列表
        格式: [(小时数, 显示名称), ...]
        """
        options = []
        try:
            # 解析配置字符串，格式为 "0.5=0.5小时,1=1小时,2=2小时"
            option_pairs = cls.PERMISSION_DURATION_OPTIONS.split(',')
            for pair in option_pairs:
                if '=' in pair:
                    hours_str, display_name = pair.split('=', 1)
                    hours = float(hours_str)
                    options.append((hours, display_name.strip()))
        except Exception as e:
            logger.error(f"解析时长选项配置失败: {e}")
            # 返回默认选项
            options = [(0.5, '0.5小时'), (1, '1小时'), (2, '2小时')]
        return options
    
    @classmethod
    def log_config_summary(cls):
        """记录配置摘要信息"""
        logger.info("=== 配置摘要 ===")
        logger.info(f"数据库主机: {cls.DATABASE_HOST}")
        logger.info(f"数据库名称: {cls.DATABASE_NAME}")
        logger.info(f"调试模式: {cls.DEBUG}")
        logger.info(f"钉钉Webhook URL: {cls.DINGTALK_WEBHOOK_URL}")
        logger.info(f"SSH连接超时: {cls.SSH_CONNECT_TIMEOUT}秒")
        logger.info(f"后台任务启用: {cls.RUN_BACKGROUND_TASKS}")
        logger.info(f"OTP验证窗口期: {cls.OTP_VALID_WINDOW}")
        logger.info("=============== ")