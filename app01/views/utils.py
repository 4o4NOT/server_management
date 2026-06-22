"""
工具视图：服务器查询、账户检查、过期时间查询
"""
import logging

from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods, require_GET
from django.core.paginator import Paginator, EmptyPage
from django.db.models import Q

from app01.models import ServerInfo, PermissionApplication
from app01.views.common import logger

logger = logging.getLogger(__name__)


@login_required
@require_GET
def available_servers_for_user(request):
    """获取用户可申请的服务器列表"""
    try:
        search_query = request.GET.get('search', '').strip()
        servers_queryset = ServerInfo.objects.all().values(
            'id', 'host', 'port', 'username', 'description'
        )

        if search_query:
            servers_queryset = servers_queryset.filter(
                Q(host__icontains=search_query) |
                Q(username__icontains=search_query) |
                Q(description__icontains=search_query)
            )

        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        paginator = Paginator(servers_queryset, page_size)

        try:
            servers_page = paginator.page(page)
        except EmptyPage:
            servers_page = paginator.page(paginator.num_pages)

        servers_list = list(servers_page)

        return JsonResponse({
            'status': 'success', 'data': servers_list,
            'total': paginator.count, 'current_page': page,
            'total_pages': paginator.num_pages
        })
    except Exception as e:
        logger.error(f"获取可申请服务器列表失败: {str(e)}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': f'获取服务器列表失败: {str(e)}'}, status=500)


@login_required
@require_GET
def check_server_account_exists(request):
    """检查服务器和账户名组合是否存在"""
    try:
        host = request.GET.get('host')
        username = request.GET.get('username')

        if not host or not username:
            return JsonResponse({'status': 'error', 'message': '缺少主机地址或用户名参数'}, status=400)

        exists = ServerInfo.objects.filter(host=host, username=username).exists()
        return JsonResponse({'status': 'success', 'exists': exists})
    except Exception as e:
        logger.error(f"检查服务器账户组合失败: {str(e)}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': '检查失败'}, status=500)


@require_GET
def check_server_password_expiration(request):
    """查询服务器账户密码过期时间"""
    try:
        host = request.GET.get('host')
        username = request.GET.get('username')

        if not host or not username:
            return JsonResponse({'status': 'error', 'message': '缺少主机地址或用户名参数'}, status=400)

        try:
            server = ServerInfo.objects.get(host=host, username=username)
        except ServerInfo.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': '未找到指定的服务器信息'}, status=404)

        if not server.password_expiration_time:
            return JsonResponse({
                'status': 'success',
                'data': {'has_expiration': False, 'message': '当前服务器账户没有设置密码过期时间'}
            })

        now = timezone.now()
        if server.password_expiration_time <= now:
            return JsonResponse({
                'status': 'success',
                'data': {'has_expiration': False, 'message': '密码已过期'}
            })

        try:
            latest_application = PermissionApplication.objects.filter(
                server=server, account_name=username, status='approved'
            ).latest('approved_at')
            applicant_name = latest_application.applicant.user_name
            application_time = latest_application.approved_at.strftime('%Y-%m-%d %H:%M:%S')
        except PermissionApplication.DoesNotExist:
            applicant_name = '未知'
            application_time = '未知'

        return JsonResponse({
            'status': 'success',
            'data': {
                'has_expiration': True,
                'host': server.host, 'port': server.port,
                'username': server.username,
                'expiration': server.password_expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                'applicant': applicant_name,
                'application_time': application_time
            }
        })
    except Exception as e:
        logger.error(f"查询服务器密码过期时间失败: {str(e)}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': '查询失败'}, status=500)
