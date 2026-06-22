"""
公共函数模块 — 被 views 各子模块引用的共享工具函数
"""
import logging
import re
import json
import pyotp
import requests
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse

from app01.models import UserInfo

logger = logging.getLogger(__name__)

# 尝试从配置模块加载钉钉 Webhook URL
try:
    from server_management.config import Config
    DINGTALK_WEBHOOK_URL = Config.DINGTALK_WEBHOOK_URL
    DINGTALK_CONFIGURED = bool(DINGTALK_WEBHOOK_URL and DINGTALK_WEBHOOK_URL.strip())
    OTP_VALID_WINDOW = Config.OTP_VALID_WINDOW
except ImportError:
    DINGTALK_WEBHOOK_URL = ""
    DINGTALK_CONFIGURED = False
    OTP_VALID_WINDOW = 2


def send_dingtalk_message(title, content):
    """发送钉钉消息"""
    if not DINGTALK_WEBHOOK_URL:
        logger.warning("钉钉 Webhook URL 未配置，跳过消息发送")
        return
    try:
        headers = {'Content-Type': 'application/json'}
        data = {"msgtype": "markdown", "markdown": {"title": title, "text": content}}
        response = requests.post(DINGTALK_WEBHOOK_URL, headers=headers, data=json.dumps(data), timeout=10)
        if response.status_code == 200:
            logger.debug("钉钉消息发送成功")
        else:
            logger.error(f"钉钉消息发送失败，状态码: {response.status_code}")
    except Exception as e:
        logger.error(f"发送钉钉消息时发生错误: {str(e)}")


def find_user_by_identifier(identifier):
    """通过用户名或手机号查找用户，返回 UserInfo 对象或 None"""
    try:
        return UserInfo.objects.get(user_name=identifier)
    except UserInfo.DoesNotExist:
        try:
            return UserInfo.objects.get(phone=identifier)
        except UserInfo.DoesNotExist:
            return None


def validate_password_complexity(password):
    """
    验证密码复杂度，返回 (is_valid, error_message)
    规则：至少8位，包含大小写字母、数字和特殊字符
    """
    if len(password) < 8:
        return False, '密码长度至少为8个字符'
    if not re.search(r'[A-Z]', password):
        return False, '密码必须包含至少一个大写字母'
    if not re.search(r'[a-z]', password):
        return False, '密码必须包含至少一个小写字母'
    if not re.search(r'[0-9]', password):
        return False, '密码必须包含至少一个数字'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, '密码必须包含至少一个特殊字符'
    return True, None


def verify_admin_otp(token_code):
    """
    验证管理员 OTP 令牌，返回 (is_valid, error_message, admin_user)
    """
    if not token_code or len(token_code) != 6 or not token_code.isdigit():
        return False, '验证码必须是6位数字', None

    admin_user = UserInfo.objects.filter(
        otp_secret__isnull=False, otp_active=True
    ).first()

    if not admin_user:
        return False, '未找到已激活的管理员令牌', None

    totp = pyotp.TOTP(admin_user.otp_secret)
    if not totp.verify(token_code, valid_window=OTP_VALID_WINDOW):
        return False, '令牌验证失败', None

    return True, None, admin_user


def admin_required(user):
    """检查用户是否为管理员，返回 JsonResponse 或 None（通过）"""
    if not user.is_superuser:
        return JsonResponse({'status': 'error', 'message': '权限不足'}, status=403)
    return None


def jwt_login_required(view_func):
    """自定义JWT登录装饰器"""
    def _wrapped_view(request, *args, **kwargs):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            if request.path.startswith('/api/'):
                return JsonResponse({'status': 'error', 'message': '未认证'}, status=401)
            return redirect(reverse('login'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view
