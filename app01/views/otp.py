"""
OTP令牌管理视图：管理员绑定、验证、生成、重置令牌
"""
import json
import logging
import hashlib
from base64 import b64encode
from io import BytesIO

import pyotp
import qrcode

from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods

from app01.models import UserInfo
from app01.views.common import verify_admin_otp, admin_required, logger

logger = logging.getLogger(__name__)


@login_required
def otp_management(request):
    """OTP验证管理视图（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    user = request.user

    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.totp.TOTP(user.otp_secret, interval=30, digits=6, digest=hashlib.sha1)
    otp_uri = totp.provisioning_uri(name=user.user_name, issuer_name="权限管理系统")

    img = qrcode.make(otp_uri)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = b64encode(buffer.getvalue()).decode()

    return render(request, 'otp_management.html', {
        'qr_code': img_str,
        'otp_secret': user.otp_secret
    })


@login_required
@require_http_methods(["GET"])
def system_token_management(request):
    """系统唯一令牌管理接口"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    admin_with_token = UserInfo.objects.filter(otp_secret__isnull=False).first()
    current_user = request.user

    if not admin_with_token:
        secret = pyotp.random_base32()
        current_user.otp_secret = secret
        current_user.otp_active = False
        current_user.save()

        totp = pyotp.totp.TOTP(secret, interval=30, digits=6, digest=hashlib.sha1)
        otp_uri = totp.provisioning_uri(name=current_user.user_name, issuer_name="权限管理系统")
        img = qrcode.make(otp_uri)
        buffer = BytesIO()
        img.save(buffer, 'PNG')
        img_str = b64encode(buffer.getvalue()).decode()

        return JsonResponse({
            'status': 'success', 'otp_secret': secret,
            'qr_code': img_str, 'message': '已为您生成系统密钥，请扫码绑定并验证'
        })
    elif admin_with_token.id == current_user.id:
        secret = current_user.otp_secret
        if not secret:
            secret = pyotp.random_base32()
            current_user.otp_secret = secret
            current_user.otp_active = False
            current_user.save()

        totp = pyotp.totp.TOTP(secret, interval=30, digits=6, digest=hashlib.sha1)
        otp_uri = totp.provisioning_uri(name=current_user.user_name, issuer_name="权限管理系统")
        img = qrcode.make(otp_uri)
        buffer = BytesIO()
        img.save(buffer, 'PNG')
        img_str = b64encode(buffer.getvalue()).decode()

        return JsonResponse({
            'status': 'success', 'otp_secret': secret,
            'qr_code': img_str, 'message': '请使用认证器扫描二维码并输入验证码完成绑定'
        })
    else:
        return JsonResponse({
            'status': 'error',
            'message': f'系统中已有密钥，请向管理员 {admin_with_token.user_name} 获取'
        })


@login_required
def verify_token_page(request):
    """令牌验证页面视图"""
    return render(request, 'verify_token_page.html')


@login_required
@require_http_methods(["POST"])
def verify_current_user_token(request):
    """验证当前用户的OTP令牌（用于激活自己的令牌）"""
    user = request.user

    try:
        admin_resp = admin_required(user)
        if admin_resp:
            return admin_resp

        if not user.otp_secret:
            return JsonResponse({'status': 'error', 'message': '用户没有OTP密钥'}, status=400)

        data = json.loads(request.body)
        token_code = data.get('token_code', '').strip()

        if not token_code or len(token_code) != 6 or not token_code.isdigit():
            return JsonResponse({'status': 'error', 'message': '验证码必须是6位数字'}, status=400)

        totp = pyotp.TOTP(user.otp_secret, interval=30, digits=6, digest=hashlib.sha1)
        from server_management.config import Config
        if totp.verify(token_code, valid_window=Config.OTP_VALID_WINDOW):
            user.otp_active = True
            user.save()
            return JsonResponse({'status': 'success', 'message': '令牌验证成功，已激活！'})
        else:
            return JsonResponse({'status': 'error', 'message': '令牌验证失败，请重试'})

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': '请求数据格式错误'}, status=400)
    except Exception as e:
        logger.error(f"验证当前用户令牌失败: {str(e)}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': f'验证失败: {str(e)}'}, status=500)


@login_required
@require_http_methods(["GET"])
def get_user_token(request, user_id):
    """获取指定用户的令牌信息（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)
        return JsonResponse({
            'status': 'success',
            'otp_secret': user.otp_secret,
            'otp_active': user.otp_active
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)


@login_required
@require_http_methods(["POST"])
def generate_token(request, user_id):
    """为指定用户生成新的令牌（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        existing_token_user = UserInfo.objects.filter(
            otp_secret__isnull=False
        ).exclude(id=user_id).first()
        if existing_token_user:
            return JsonResponse({
                'status': 'error',
                'message': f'系统中已存在令牌（属于用户：{existing_token_user.user_name}），不允许多个令牌'
            }, status=400)

        user = UserInfo.objects.get(id=user_id)
        user.otp_secret = pyotp.random_base32()
        user.otp_active = False
        user.save()

        return JsonResponse({
            'status': 'success', 'message': '令牌生成成功',
            'otp_secret': user.otp_secret
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)


@login_required
@require_http_methods(["POST"])
def verify_token(request, user_id):
    """验证用户输入的令牌验证码（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)
        token_code = request.POST.get('token_code', '')

        totp = pyotp.TOTP(user.otp_secret, interval=30, digits=6, digest='sha1',
                          name=user.user_name, issuer='权限管理系统')
        if totp.verify(token_code, valid_window=2):
            user.otp_active = True
            user.save()
            return JsonResponse({'status': 'success', 'message': '令牌验证成功，已激活！'})
        else:
            return JsonResponse({'status': 'error', 'message': '令牌验证失败，请重试'})
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)


@login_required
@require_http_methods(["POST"])
def reset_token(request, user_id):
    """重置指定用户的令牌（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)
        user.otp_secret = None
        user.otp_active = False
        user.save()
        return JsonResponse({'status': 'success', 'message': '令牌已重置，用户需要重新绑定'})
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)
