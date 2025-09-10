import logging
import re
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from .models import UserInfo  # 导入用户模型

logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """全局JWT认证中间件"""

    # 更新公共路径列表
    PUBLIC_PATHS = [
        '/login/',
        '/register/',
        '/admin/',
        '/static/',
        '/favicon.ico',
        '/health/',
        '/api/check-token/',
    ]

    def __init__(self, get_response=None):
        super().__init__(get_response)
        # 预编译正则表达式以提高性能
        self.static_regex = re.compile(r'^/static/')
        self.media_regex = re.compile(r'^/media/')

    def process_request(self, request):
        """处理每个请求前的中间件逻辑"""
        # 添加详细日志
        logger.debug(f"请求路径: {request.path}")
        logger.debug(f"请求方法: {request.method}")

        # 检查是否为静态文件或媒体文件
        if self.static_regex.match(request.path) or self.media_regex.match(request.path):
            logger.debug(f"静态/媒体文件: {request.path} - 跳过认证")
            return None

        # 检查是否为公共路径 - 使用精确匹配
        if request.path in self.PUBLIC_PATHS:
            logger.debug(f"公共路径: {request.path} - 跳过认证")
            return None

        logger.debug(f"检查认证: {request.path}")

        # 尝试从cookie获取JWT令牌
        token = request.COOKIES.get('access_token')

        # 尝试从Authorization头获取令牌
        if not token:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        # 如果没有令牌则重定向到登录页
        if not token:
            logger.warning(f"未找到访问令牌: {request.path}")
            # 对于API请求返回JSON错误
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'status': 'error',
                    'message': '未提供访问令牌'
                }, status=401)
            return HttpResponseRedirect(reverse('login'))

        # 验证令牌
        try:
            access_token = AccessToken(token)
            # 将用户添加到请求对象
            user_id = access_token['user_id']
            try:
                # 从数据库获取用户
                user = UserInfo.objects.get(id=user_id)
                request.user = user
                logger.debug(f"令牌验证成功: 用户 {user.user_name}")
            except UserInfo.DoesNotExist:
                logger.error(f"用户ID {user_id} 不存在")
                # 对于API请求返回JSON错误
                if request.path.startswith('/api/'):
                    return JsonResponse({
                        'status': 'error',
                        'message': '用户不存在'
                    }, status=404)
                # 用户不存在则清除cookie并重定向到登录页
                response = HttpResponseRedirect(reverse('login'))
                response.delete_cookie('access_token')
                return response
        except TokenError as e:
            logger.warning(f"令牌验证失败: {str(e)}")
            # 对于API请求返回JSON错误
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'status': 'error',
                    'message': '令牌无效或已过期'
                }, status=401)
            # 令牌无效或过期则清除cookie并重定向到登录页
            response = HttpResponseRedirect(reverse('login'))
            response.delete_cookie('access_token')
            return response

        return None


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # 移除Server头信息
        response['Server'] = ''
        
        # 可以添加其他安全头信息
        # response['X-Content-Type-Options'] = 'nosniff'
        # response['X-Frame-Options'] = 'DENY'
        # response['X-XSS-Protection'] = '1; mode=block'
        
        return response