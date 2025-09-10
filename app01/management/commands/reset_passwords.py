import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from app01.models import ServerInfo
from app01.views import update_server_password, check_expired_passwords

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = '检查并更新过期的服务器密码'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help='检查间隔（秒），默认为60秒',
        )
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='以守护进程模式运行',
        )

    def handle(self, *args, **options):
        interval = options['interval']
        daemon = options['daemon']
        
        if daemon:
            self.run_as_daemon(interval)
        else:
            logger.info("执行一次密码过期检查")
            updated_count = check_expired_passwords()
            self.stdout.write(
                self.style.SUCCESS(f'成功更新了 {updated_count} 个服务器的密码')
            )

    def run_as_daemon(self, interval):
        import time
        logger.info(f"以守护进程模式运行，检查间隔: {interval} 秒")
        self.stdout.write(f"以守护进程模式运行，检查间隔: {interval} 秒")
        
        while True:
            try:
                logger.info("开始执行定时任务：检查并更新过期的服务器密码")
                updated_count = check_expired_passwords()
                logger.info(f"定时任务执行完成，共更新了 {updated_count} 个服务器的密码")
                self.stdout.write(
                    self.style.SUCCESS(f'成功更新了 {updated_count} 个服务器的密码')
                )
            except Exception as e:
                logger.error(f"执行定时任务时出错: {str(e)}", exc_info=True)
                self.stdout.write(
                    self.style.ERROR(f'执行定时任务时出错: {str(e)}')
                )
            
            time.sleep(interval)