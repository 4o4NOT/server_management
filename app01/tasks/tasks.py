import os
import logging
import threading
import time
from django.utils import timezone
from django.conf import settings
from app01.views import check_expired_passwords

logger = logging.getLogger(__name__)


def password_check_task():
    """密码检查任务"""
    interval = getattr(settings, 'PASSWORD_CHECK_INTERVAL', 3600)

    while True:
        try:
            updated_count = check_expired_passwords()
            if updated_count > 0:
                logger.info(f"后台任务执行完成，共更新了 {updated_count} 个服务器的密码")
        except Exception as e:
            logger.error(f"后台任务执行时出错: {str(e)}", exc_info=True)

        time.sleep(interval)


def start_background_tasks():
    """启动后台任务"""
    logger.info("尝试启动后台任务线程")

    try:
        password_thread = threading.Thread(
            target=password_check_task,
            daemon=True,
            name="PasswordCheckThread"
        )
        password_thread.start()
        logger.info(f"后台任务线程已启动，线程名: {password_thread.name}")
    except Exception as e:
        logger.error(f"启动后台任务线程时出错: {str(e)}", exc_info=True)
