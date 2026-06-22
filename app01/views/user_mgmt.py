"""
用户管理视图：管理员对用户进行增删改查
"""
import json
import logging

from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage
from django.db.models import Q

from app01.models import UserInfo
from app01.views.common import admin_required, logger

logger = logging.getLogger(__name__)


@login_required
def user_management(request):
    """用户管理视图，管理员可以查看和管理所有用户"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return render(request, '403.html', status=403)

    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', 'all')
    admin_filter = request.GET.get('admin', 'all')

    users = UserInfo.objects.all().order_by('-date_joined')

    if search_query:
        users = users.filter(
            Q(user_name__icontains=search_query) | Q(phone__icontains=search_query)
        )
    if status_filter != 'all':
        users = users.filter(is_active=(status_filter == 'active'))
    if admin_filter != 'all':
        users = users.filter(is_superuser=(admin_filter == 'admin'))

    total = users.count()
    stats = {
        'total': total,
        'active': users.filter(is_active=True).count(),
        'inactive': users.filter(is_active=False).count(),
        'admin': users.filter(is_superuser=True).count(),
        'regular': total - users.filter(is_superuser=True).count()
    }

    page = request.GET.get('page', 1)
    paginator = Paginator(users, 10)
    try:
        users_page = paginator.page(page)
    except EmptyPage:
        users_page = paginator.page(paginator.num_pages)
    except Exception:
        users_page = paginator.page(1)

    return render(request, 'user_management.html', {
        'users': users_page,
        'search_query': search_query,
        'status_filter': status_filter,
        'admin_filter': admin_filter,
        'stats': stats
    })


@login_required
@require_http_methods(["POST"])
def delete_user(request, user_id):
    """删除用户（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)

        if user.is_superuser:
            return JsonResponse({'status': 'error', 'message': '不能删除管理员用户'}, status=403)
        if user.id == request.user.id:
            return JsonResponse({'status': 'error', 'message': '不能删除当前登录的用户'}, status=400)

        user.delete()
        return JsonResponse({'status': 'success', 'message': '用户删除成功'})
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)
    except Exception as e:
        logger.error(f"删除用户失败: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'删除失败: {str(e)}'}, status=500)


@login_required
@require_http_methods(["POST"])
def toggle_user_active(request, user_id):
    """切换用户激活状态（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)

        if user.is_superuser and user.id != request.user.id:
            return JsonResponse({'status': 'error', 'message': '不能操作其他管理员账户'}, status=403)
        if user.id == request.user.id:
            return JsonResponse({'status': 'error', 'message': '不能禁用当前登录的用户'}, status=400)

        user.is_active = not user.is_active
        user.save()

        new_status = "禁用" if user.is_active else "启用"
        return JsonResponse({
            'status': 'success',
            'message': f'用户已{new_status}',
            'is_active': user.is_active,
            'action': new_status
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)
    except Exception as e:
        logger.error(f"切换用户状态失败: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'状态更新失败: {str(e)}'}, status=500)


@login_required
@require_http_methods(["POST"])
def reset_password(request, user_id):
    """重置用户密码（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        user = UserInfo.objects.get(id=user_id)

        if user.is_superuser and user.id != request.user.id:
            return JsonResponse({'status': 'error', 'message': '不能重置其他管理员的密码'}, status=403)

        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_new_password')

        if not new_password or new_password != confirm_password:
            return JsonResponse({'status': 'error', 'message': '两次输入的密码不一致'})

        logger.info(f"管理员 {request.user.user_name} 重置用户 {user.user_name} 的密码")
        user.set_password(new_password)
        user.save()

        return JsonResponse({'status': 'success', 'message': '密码重置成功'})
    except UserInfo.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': '用户不存在'}, status=404)
    except Exception as e:
        logger.error(f"重置密码失败: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'重置密码失败: {str(e)}'}, status=500)


@login_required
@require_http_methods(["POST"])
def bulk_delete_users(request):
    """批量删除用户（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        data = json.loads(request.body)
        user_ids = data.get('user_ids', [])

        if not user_ids or not isinstance(user_ids, list):
            return JsonResponse({'status': 'error', 'message': '未提供有效的用户ID列表'}, status=400)

        users_to_delete = UserInfo.objects.filter(id__in=user_ids)
        for user in users_to_delete:
            if user.is_superuser:
                return JsonResponse({'status': 'error', 'message': '不能删除管理员用户'}, status=403)
            if user.id == request.user.id:
                return JsonResponse({'status': 'error', 'message': '不能删除当前登录的用户'}, status=400)

        deleted_count, _ = users_to_delete.delete()
        return JsonResponse({'status': 'success', 'message': f'成功删除 {deleted_count} 个用户'})
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': '请求数据格式错误'}, status=400)
    except Exception as e:
        logger.error(f"批量删除用户失败: {str(e)}")
        return JsonResponse({'status': 'error', 'message': f'批量删除失败: {str(e)}'}, status=500)
