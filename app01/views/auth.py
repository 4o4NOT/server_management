"""
认证相关视图：登录、注册、登出、修改密码、令牌刷新、自定义认证后端
"""
import logging
import re
from datetime import timedelta

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.conf import settings

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

from app01.models import UserInfo
from app01.views.common import (
    find_user_by_identifier,
    validate_password_complexity,
    logger
)

logger = logging.getLogger(__name__)


class CustomModelBackend(ModelBackend):
    """自定义认证后端，支持用户名或手机号登录"""

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = find_user_by_identifier(username)
        if user is None:
            return None
        if user.check_password(password):
            return user
        return None


def user_login(request):
    """登录视图"""
    logger.debug("收到登录请求")

    if request.method == 'GET':
        return render(request, 'login.html')

    if request.method == 'POST':
        identifier = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        user = find_user_by_identifier(identifier)
        if not user:
            return JsonResponse({'status': 'error', 'message': '用户名或密码不正确'})

        if not user.check_password(password):
            logger.warning(f"登录失败: 用户 {identifier} 密码错误")
            return JsonResponse({'status': 'error', 'message': '用户名或密码不正确'})

        if not user.is_active:
            logger.warning(f"尝试登录的被禁用用户: {user.user_name}")
            return JsonResponse({'status': 'error', 'message': '账户已被禁用，请联系管理员'})

        user.last_login = timezone.now()
        user.save()

        backend = CustomModelBackend()
        authenticated_user = backend.authenticate(request, username=identifier, password=password)

        if authenticated_user is not None:
            auth_login(request, authenticated_user, backend='app01.views.auth.CustomModelBackend')
            logger.info(f"用户 {user.user_name} 登录成功")
        else:
            logger.error("认证后端返回的用户为空")
            return JsonResponse({'status': 'error', 'message': '认证失败'})

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = JsonResponse({
            'status': 'success',
            'message': '登录成功',
            'redirect_url': '/index/'
        })
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            max_age=int(timedelta(hours=3).total_seconds()),
            samesite='Lax',
            secure=settings.SECURE_COOKIE
        )
        return response
    return None


def user_logout(request):
    """登出视图"""
    logger.info("用户登出")
    try:
        auth_logout(request)
        response = redirect(reverse('login'))
        response.delete_cookie('access_token', path='/', domain=settings.SESSION_COOKIE_DOMAIN)
        return response
    except Exception as e:
        logger.error(f"登出过程中发生错误: {str(e)}")
        return redirect(reverse('login'))


def register(request):
    """注册视图"""
    logger.debug("收到注册请求，方法: %s", request.method)

    if request.method == 'GET':
        return render(request, 'register.html')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        phone = request.POST.get('phone', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirmPassword', '')

        if password != confirm_password:
            return JsonResponse({'status': 'error', 'message': '两次输入的密码不一致'})

        if not re.match(r'^[一-龥]{2,4}$', username):
            return JsonResponse({'status': 'error', 'message': '请输入2-4个汉字的中文姓名'})

        if not re.match(r'^\d{11}$', phone):
            return JsonResponse({'status': 'error', 'message': '手机号格式不正确'})

        is_valid, error_msg = validate_password_complexity(password)
        if not is_valid:
            return JsonResponse({'status': 'error', 'message': error_msg})

        if UserInfo.objects.filter(phone=phone).exists():
            return JsonResponse({'status': 'error', 'message': '该手机号已被注册'})

        if UserInfo.objects.filter(user_name=username).exists():
            return JsonResponse({'status': 'error', 'message': '该用户名已被使用'})

        try:
            user = UserInfo(user_name=username, phone=phone)
            user.set_password(password)
            user.save()
            return JsonResponse({'status': 'success', 'message': '注册成功！'})
        except Exception as e:
            logger.error(f"注册失败: {str(e)}")
            return JsonResponse({'status': 'error', 'message': f'注册失败: {str(e)}'})
    return None


@login_required
def profile(request):
    """用户资料视图"""
    user = request.user
    context = {
        'username': user.user_name,
        'phone': user.phone,
        'join_date': user.date_joined.strftime('%Y-%m-%d'),
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else '从未登录'
    }
    return render(request, 'profile.html', context)


@login_required
def change_password(request):
    """修改密码视图"""
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        user = request.user

        if not user.check_password(old_password):
            return JsonResponse({'status': 'error', 'message': '旧密码不正确'})

        if new_password != confirm_password:
            return JsonResponse({'status': 'error', 'message': '两次输入的新密码不一致'})

        is_valid, error_msg = validate_password_complexity(new_password)
        if not is_valid:
            return JsonResponse({'status': 'error', 'message': error_msg})

        user.set_password(new_password)
        user.save()
        auth_login(request, user, backend='app01.views.auth.CustomModelBackend')
        return JsonResponse({'status': 'success', 'message': '密码修改成功'})

    return render(request, 'change_password.html')


def refresh_token(request):
    """刷新JWT令牌的API视图"""
    if not request.user.is_authenticated:
        return JsonResponse({'status': 'error', 'message': '用户未认证'}, status=401)

    try:
        user = request.user
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        response = JsonResponse({'status': 'success', 'message': '令牌刷新成功'})
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            max_age=int(timedelta(hours=3).total_seconds()),
            samesite='Lax',
            secure=settings.SECURE_COOKIE
        )
        logger.info(f"用户 {user.user_name} 刷新令牌成功")
        return response
    except Exception as e:
        logger.error(f"令牌刷新失败: {str(e)}")
        return JsonResponse({'status': 'error', 'message': '令牌刷新失败'}, status=500)


def check_token(request):
    """检查令牌有效性"""
    token = request.COOKIES.get('access_token')
    if not token:
        return JsonResponse({'valid': False})
    try:
        AccessToken(token)
        return JsonResponse({'valid': True})
    except TokenError:
        return JsonResponse({'valid': False})
