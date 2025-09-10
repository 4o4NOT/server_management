from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)


class UserInfoAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        logger.debug("自定义认证开始: %s", username)
        UserModel = get_user_model()
        try:
            # 尝试通过用户名查找
            logger.debug("用户名查询: %s", username)
            user = UserModel.objects.get(user_name=username)
            logger.debug("找到用户: %s", user.user_name)
        except UserModel.DoesNotExist:
            try:
                # 尝试通过手机号查找
                logger.debug("手机号查询: %s", username)
                user = UserModel.objects.get(phone=username)
                logger.debug("找到用户: %s", user.user_name)
            except UserModel.DoesNotExist:
                logger.debug("未找到用户: %s", username)
                return None

        logger.debug("验证密码")
        if user.check_password(password):
            logger.info("认证成功: %s", user.user_name)
            return user

        logger.debug("密码验证失败")
        return None
