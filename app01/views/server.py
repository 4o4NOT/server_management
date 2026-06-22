"""
服务器管理视图：CRUD、SSH连接测试、密码更新
"""
import json
import logging
import secrets
import string

import paramiko

from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage
from django.db.models import Q
from django.views.decorators.http import require_http_methods

from app01.models import ServerInfo
from app01.models import DecryptionError
from app01.views.common import admin_required, logger

logger = logging.getLogger(__name__)


def test_ssh_connection(host, port, username, password):
    """测试SSH连接"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=host, port=port, username=username,
            password=password, timeout=10, look_for_keys=False
        )
        stdin, stdout, stderr = ssh.exec_command('echo "SSH connection test successful"')
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()

        if exit_status == 0:
            return {'success': True, 'message': 'SSH连接测试成功'}
        else:
            return {'success': False, 'message': 'SSH命令执行失败'}

    except paramiko.AuthenticationException:
        if ssh:
            ssh.close()
        return {'success': False, 'message': 'SSH认证失败，请检查用户名和密码'}
    except paramiko.SSHException as e:
        if ssh:
            ssh.close()
        return {'success': False, 'message': f'SSH连接异常: {str(e)}'}
    except Exception as e:
        if ssh:
            ssh.close()
        return {'success': False, 'message': f'连接失败: {str(e)}'}


def update_server_password(server, new_password, account_name):
    """通过SSH连接服务器更新密码"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.debug(f"尝试连接服务器 {server.host}:{server.port}")
        ssh.connect(
            hostname=server.host, port=server.port,
            username=server.username, password=server.get_password(),
            timeout=getattr(settings, 'SSH_CONNECT_TIMEOUT', 10),
            look_for_keys=False
        )
        logger.info(f"成功连接到服务器 {server.host}")

        # 通过 stdin 传递密码对，避免 shell 注入风险
        # root 用户无需 sudo，使用完整路径（非交互 SSH 可能 PATH 不含 /usr/sbin）
        if server.username == 'root':
            command = "/usr/sbin/chpasswd 2>&1"
        else:
            command = "sudo /usr/sbin/chpasswd 2>&1"
        password_pair = f"{account_name}:{new_password}\n"

        logger.debug(f"执行密码更新命令，目标服务器: {server.host}")
        stdin, stdout, stderr = ssh.exec_command(
            command,
            timeout=getattr(settings, 'SSH_EXEC_TIMEOUT', 30)
        )
        stdin.write(password_pair)
        stdin.channel.shutdown_write()

        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')

        ssh.close()

        if exit_status == 0:
            logger.info(f"服务器 {server.host} 密码更新成功")
            return True
        else:
            logger.error(f"服务器密码更新失败, 退出状态: {exit_status}, 错误信息: {error_output}")
            return False

    except paramiko.AuthenticationException:
        logger.error(f"SSH认证失败: 服务器 {server.host}")
        if ssh:
            ssh.close()
        return False
    except paramiko.SSHException as e:
        logger.error(f"SSH连接异常: {str(e)}")
        if ssh:
            ssh.close()
        return False
    except Exception as e:
        logger.error(f"更新服务器密码异常: {str(e)}", exc_info=True)
        if ssh:
            ssh.close()
        return False


@login_required
def server_management(request):
    """服务器管理视图（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return admin_resp
        return render(request, '403.html', status=403)

    from django.shortcuts import render

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 10))
            search_query = request.GET.get('search', '').strip()

            servers = ServerInfo.objects.all()
            if search_query:
                servers = servers.filter(
                    Q(host__icontains=search_query) | Q(username__icontains=search_query)
                )

            total_servers = servers.count()
            paginator = Paginator(servers, page_size)
            try:
                servers_page = paginator.page(page)
            except EmptyPage:
                servers_page = paginator.page(paginator.num_pages)

            server_list = []
            for server in servers_page:
                server_list.append({
                    'id': server.id, 'host': server.host,
                    'port': server.port, 'username': server.username,
                    'password': '******', 'description': server.description or ''
                })

            return JsonResponse({
                'status': 'success',
                'data': {
                    'servers': server_list, 'total': total_servers,
                    'current_page': page, 'total_pages': paginator.num_pages
                }
            })
        except Exception as e:
            logger.error(f"获取服务器列表失败: {str(e)}")
            return JsonResponse({'status': 'error', 'message': '获取服务器列表失败'}, status=500)

    return render(request, 'server_management.html')


@login_required
@require_http_methods(["POST"])
def add_server(request):
    """添加服务器（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        resp = admin_resp
        resp['Server'] = ''
        return resp

    try:
        if request.content_type and 'application/json' in request.content_type:
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError as e:
                resp = JsonResponse({'status': 'error', 'message': f'JSON数据格式错误: {str(e)}'}, status=400)
                resp['Server'] = ''
                return resp
        elif request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            from django.http import QueryDict
            form_data = QueryDict(request.body.decode('utf-8'))
            data = {
                'host': form_data.get('host', ''), 'port': form_data.get('port', '22'),
                'username': form_data.get('username', ''), 'password': form_data.get('password', ''),
                'description': form_data.get('description', '')
            }
            try:
                data['port'] = int(data['port'])
            except (ValueError, TypeError):
                data['port'] = 22
        else:
            resp = JsonResponse({'status': 'error', 'message': f'不支持的内容类型: {request.content_type}'}, status=400)
            resp['Server'] = ''
            return resp

        host = data.get('host')
        port = data.get('port', 22)
        username = data.get('username')
        password = data.get('password')
        description = data.get('description', '')

        if not host or not username or not password:
            resp = JsonResponse({'status': 'error', 'message': '主机地址、用户名和密码不能为空'}, status=400)
            resp['Server'] = ''
            return resp

        if ServerInfo.objects.filter(host=host, username=username).exists():
            resp = JsonResponse({'status': 'error', 'message': '该主机地址和用户名组合已存在'}, status=400)
            resp['Server'] = ''
            return resp

        ssh_test_result = test_ssh_connection(host, port, username, password)
        if not ssh_test_result['success']:
            resp = JsonResponse({'status': 'error', 'message': f'SSH连接测试失败: {ssh_test_result["message"]}'}, status=400)
            resp['Server'] = ''
            return resp

        server = ServerInfo(
            host=host, port=port, username=username,
            description=description, last_password_change=timezone.now(),
            password_change_type='manual'
        )
        server.set_password(password)
        server.save()

        logger.info(f"管理员 {request.user.user_name} 添加了服务器 {host}:{port}")
        resp = JsonResponse({'status': 'success', 'message': '服务器添加成功', 'server_id': server.id})
        resp['Server'] = ''
        return resp
    except Exception as e:
        logger.error(f"添加服务器失败: {str(e)}", exc_info=True)
        resp = JsonResponse({'status': 'error', 'message': f'服务器添加失败: {str(e)}'}, status=400)
        resp['Server'] = ''
        return resp


@login_required
@require_http_methods(["POST"])
def update_server(request, server_id):
    """更新服务器信息（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        server = ServerInfo.objects.get(id=server_id)
        data = json.loads(request.body)

        old_host = server.host
        server.host = data.get('host', server.host)
        server.port = data.get('port', server.port)
        server.username = data.get('username', server.username)
        server.description = data.get('description', server.description)

        if 'password' in data and data['password']:
            server.set_password(data['password'])

        server.save()
        logger.info(f"管理员 {request.user.user_name} 更新了服务器 {old_host} -> {server.host}")

        resp = JsonResponse({'status': 'success', 'message': '服务器更新成功'})
        resp['Server'] = ''
        return resp
    except ServerInfo.DoesNotExist:
        resp = JsonResponse({'status': 'error', 'message': '服务器不存在'}, status=404)
        resp['Server'] = ''
        return resp
    except Exception as e:
        logger.error(f"更新服务器失败: {str(e)}")
        resp = JsonResponse({'status': 'error', 'message': f'更新失败: {str(e)}'}, status=500)
        resp['Server'] = ''
        return resp


@login_required
@require_http_methods(["POST"])
def delete_server(request, server_id):
    """删除服务器（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        resp = admin_resp
        resp['Server'] = ''
        return resp

    try:
        server = ServerInfo.objects.get(id=server_id)
        server.delete()
        resp = JsonResponse({'status': 'success', 'message': '服务器删除成功'})
        resp['Server'] = ''
        return resp
    except ServerInfo.DoesNotExist:
        resp = JsonResponse({'status': 'error', 'message': '服务器不存在'}, status=404)
        resp['Server'] = ''
        return resp
    except Exception as e:
        logger.error(f"删除服务器失败: {str(e)}")
        resp = JsonResponse({'status': 'error', 'message': f'删除失败: {str(e)}'}, status=500)
        resp['Server'] = ''
        return resp


@login_required
@require_http_methods(["POST"])
def decrypt_server_password(request, server_id):
    """解密服务器密码（需要OTP验证）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        data = json.loads(request.body)
        token_code = data.get('token_code', '').strip()

        from app01.views.common import verify_admin_otp
        is_valid, error_msg, admin_user = verify_admin_otp(token_code)
        if not is_valid:
            return JsonResponse({'status': 'error', 'message': error_msg},
                                status=401 if error_msg == '令牌验证失败' else 400)

        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': '服务器不存在'}, status=404)

        try:
            decrypted_password = server.get_password()
            if isinstance(decrypted_password, bytes):
                decrypted_password = decrypted_password.decode('utf-8')
            logger.info(f"管理员 {request.user.user_name} 成功解密了服务器 {server.host} 的密码")
        except DecryptionError as e:
            logger.error(f"解密服务器 {server.host} 密码失败: {str(e)}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
        except Exception as e:
            logger.error(f"解密服务器 {server.host} 密码失败: {str(e)}")
            return JsonResponse({'status': 'error', 'message': '密码解密失败'}, status=500)

        return JsonResponse({'status': 'success', 'password': decrypted_password})

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': '请求数据格式错误'}, status=400)
    except Exception as e:
        logger.error(f"解密服务器密码失败: {str(e)}", exc_info=True)
        return JsonResponse({'status': 'error', 'message': '解密失败'}, status=500)
