import os
import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)


class TasksConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app01.tasks'

    def ready(self):
        logger.info("TasksConfig.ready() 被调用")

        # 只在主进程中启动后台任务（避免 runserver reloader 重复启动）
        if os.environ.get('RUN_MAIN') != 'true':
            logger.info("不是主进程，跳过后台任务启动")
            return

        # 检查是否启用后台任务
        run_background = getattr(settings, 'RUN_BACKGROUND_TASKS', False)
        logger.info(f"RUN_BACKGROUND_TASKS 设置: {run_background}")

        if not run_background:
            logger.info("RUN_BACKGROUND_TASKS 为 False，跳过后台任务启动")
            return

        # 生产环境（DEBUG=False）或显式启用时启动后台任务
        logger.info("正在启动后台任务...")
        try:
            from . import tasks
            tasks.start_background_tasks()
            logger.info("后台任务启动函数已调用")
        except Exception as e:
            logger.error(f"启动后台任务时出错: {str(e)}", exc_info=True)
