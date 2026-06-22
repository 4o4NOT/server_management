"""
页面视图：首页、服务器列表页、批量申请页
"""
import json
import logging
import sys

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_page
from django.core.cache import cache

from app01.models import ServerInfo
from app01.views.common import DINGTALK_CONFIGURED

logger = logging.getLogger(__name__)

try:
    from server_management.config import Config
except ImportError:
    class Config:
        @staticmethod
        def get_duration_options():
            return [(0.5, '0.5小时'), (1, '1小时'), (2, '2小时')]
        PASSWORD_DISPLAY_MODE = 'auto_copy'


@login_required
def index(request):
    """首页视图"""
    user = request.user
    logger.info(f"用户 {user.user_name} 访问首页")

    servers_queryset = ServerInfo.objects.all().values(
        'id', 'host', 'port', 'username', 'description'
    ).order_by('host', 'username')

    servers_by_host = {}
    for server in servers_queryset:
        host = server['host']
        if host not in servers_by_host:
            servers_by_host[host] = {'host': host, 'users': []}
        servers_by_host[host]['users'].append({
            'id': server['id'], 'port': server['port'],
            'username': server['username'], 'description': server['description'] or ''
        })

    servers = list(servers_by_host.values())
    duration_options = Config.get_duration_options()
    password_display_mode = getattr(Config, 'PASSWORD_DISPLAY_MODE', 'auto_copy')

    logger.info(f"总共加载了 {len(servers)} 个主机")

    context = {
        'servers': json.dumps(servers, ensure_ascii=False),
        'duration_options': duration_options,
        'password_display_mode': password_display_mode,
        'dingtalk_configured': json.dumps(DINGTALK_CONFIGURED),
    }

    return render(request, 'index.html', context)


@login_required
def server_list(request):
    """显示所有可申请的服务器列表页面"""
    return render(request, 'server_list.html')


@login_required
def bulk_apply(request):
    """批量权限申请页面"""
    user = request.user
    logger.info(f"用户 {user.user_name} 访问批量申请页面")

    servers = list(ServerInfo.objects.all().values(
        'id', 'host', 'port', 'username', 'description'
    ))
    duration_options = Config.get_duration_options()

    context = {
        'servers': json.dumps(servers),
        'duration_options': duration_options
    }

    return render(request, 'bulk_apply.html', context)


@login_required
def health_check(request):
    """
    健康检查端点 — 返回系统运行状态
    用于容器编排平台（如 K8s）的 liveness/readiness 探针
    """
    from django.http import JsonResponse
    from django.db import connections
    from django.conf import settings

    db_status = "ok"
    try:
        db_conn = connections['default']
        db_conn.cursor()
    except Exception:
        db_status = "error"

    from app01.models import UserInfo
    has_admin = UserInfo.objects.filter(is_superuser=True, otp_active=True).exists()

    return JsonResponse({
        'status': 'ok' if db_status == 'ok' else 'degraded',
        'database': db_status,
        'debug': settings.DEBUG,
        'otp_active': has_admin,
        'timestamp': str(__import__('django').utils.timezone.now()),
    })
