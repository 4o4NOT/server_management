import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)

class TasksConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app01.tasks'

    def ready(self):
        import os
        logger.info(f"TasksConfig.ready() 被调用")
        logger.info(f"RUN_MAIN 环境变量: {os.environ.get('RUN_MAIN')}")
        logger.info(f"DEBUG 设置: {settings.DEBUG}")
        
        if os.environ.get('RUN_MAIN') != 'true':
            logger.info("不是主进程，跳过后台任务启动")
            return
            
        if not settings.DEBUG:
            logger.info("非DEBUG模式，跳过后台任务启动")
            return
            
        run_background = getattr(settings, 'RUN_BACKGROUND_TASKS', False)
        logger.info(f"RUN_BACKGROUND_TASKS 设置: {run_background}")
        
        if run_background:
            logger.info("正在启动后台任务...")
            try:
                from . import tasks
                tasks.start_background_tasks()
                logger.info("后台任务启动函数已调用")
            except Exception as e:
                logger.error(f"启动后台任务时出错: {str(e)}", exc_info=True)
        else:
            logger.info("RUN_BACKGROUND_TASKS 为 False，跳过后台任务启动")