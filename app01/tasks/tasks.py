import logging
import threading
import time
from django.utils import timezone
from django.conf import settings
from app01.views import check_expired_passwords

logger = logging.getLogger(__name__)

def password_check_task():
    """密码检查任务"""
    interval = getattr(settings, 'PASSWORD_CHECK_INTERVAL', 3600)  # 默认1小时
    logger.info(f"密码检查任务初始化，检查间隔: {interval} 秒")
    
    while True:
        try:
            logger.info("后台任务开始：检查并更新过期的服务器密码")
            updated_count = check_expired_passwords()
            logger.info(f"后台任务执行完成，共更新了 {updated_count} 个服务器的密码")
        except Exception as e:
            logger.error(f"后台任务执行时出错: {str(e)}", exc_info=True)
        
        logger.info(f"后台任务休眠 {interval} 秒")
        time.sleep(interval)
        logger.info(f"后台任务休眠结束，开始下一轮检查")

def start_background_tasks():
    """启动后台任务"""
    logger.info("尝试启动后台任务线程")
    
    # 启动密码检查任务线程
    try:
        password_thread = threading.Thread(target=password_check_task, daemon=True, name="PasswordCheckThread")
        password_thread.start()
        logger.info(f"后台任务线程已启动，线程名: {password_thread.name}, 线程ID: {password_thread.ident}")
    except Exception as e:
        logger.error(f"启动后台任务线程时出错: {str(e)}", exc_info=True)