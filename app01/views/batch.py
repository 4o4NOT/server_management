"""
批量操作视图：批量权限申请、批量OTP验证、批量获取密码
"""
import json
import logging
import re
from datetime import timedelta

import pyotp

from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.db import transaction

from app01.models import UserInfo, ServerInfo, PermissionApplication
from app01.views.common import (
    verify_admin_otp, send_dingtalk_message, admin_required, logger,
    DINGTALK_CONFIGURED,
)
from app01.views.server import update_server_password
from app01.views.permission import generate_random_password

logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["POST"])
def bulk_apply_permission(request):
    """批量权限申请处理"""
    user = request.user

    try:
        data = json.loads(request.body)
        applications = data.get("applications", [])
        reason = data.get("reason", "").strip()
        duration = float(data.get("duration", 0))
        operation_type = data.get("operation_type", "view")
        maintenance_ticket = data.get("maintenance_ticket", "") or ""
        maintenance_ticket = maintenance_ticket.strip()

        if not applications:
            return JsonResponse({"status": "error", "message": "未提供申请信息"}, status=400)
        if not reason:
            return JsonResponse({"status": "error", "message": "请填写申请原因"}, status=400)
        if duration <= 0:
            return JsonResponse({"status": "error", "message": "申请时长必须大于0"}, status=400)
        if operation_type not in ['view', 'modify']:
            return JsonResponse({"status": "error", "message": "无效的操作类型"}, status=400)
        if operation_type == 'modify':
            if not maintenance_ticket:
                return JsonResponse({"status": "error", "message": "修改操作必须提供运维单号"}, status=400)
            if not re.match(r'^\d+$', maintenance_ticket):
                return JsonResponse({"status": "error", "message": "运维单号只能包含数字"}, status=400)

        # Bug5 修复：全部校验通过后再创建记录，包裹在事务中
        with transaction.atomic():
            # 先校验所有服务器
            validated = []
            for app in applications:
                server_id = int(app.get("server_id"))
                account_name = app.get("account_name", "").strip()
                host = app.get("host", "").strip()

                if not account_name:
                    return JsonResponse(
                        {"status": "error", "message": "账户名不能为空"}, status=400
                    )

                try:
                    server = ServerInfo.objects.get(id=server_id)
                except ServerInfo.DoesNotExist:
                    return JsonResponse(
                        {"status": "error", "message": f"服务器 {host} 不存在"}, status=404
                    )

                if server.username != account_name:
                    return JsonResponse({
                        "status": "error",
                        "message": f"账户名 {account_name} 与服务器 {host} 配置不匹配"
                    }, status=400)

                validated.append((server, account_name))

            # Bug4 修复：管理员 OTP 不存在时直接拒绝
            admin_user = UserInfo.objects.filter(
                is_superuser=True, otp_secret__isnull=False, otp_active=True
            ).first()
            if not admin_user:
                return JsonResponse(
                    {"status": "error", "message": "系统中未找到已激活的管理员令牌，无法发送验证码"},
                    status=400
                )

            unified_password = generate_random_password()
            application_results = []

            for server, account_name in validated:
                application = PermissionApplication.objects.create(
                    applicant=user, server=server, account_name=account_name,
                    reason=reason, duration=duration, status='verification_pending',
                    operation_type=operation_type,
                    maintenance_ticket=(
                        maintenance_ticket if operation_type == 'modify' else None
                    )
                )
                application_results.append({
                    'application_id': application.id, 'server_id': server.id,
                    'host': server.host, 'port': server.port,
                    'username': account_name, 'account_name': account_name,
                    'applicant': user.user_name, 'duration': duration,
                    'operation_type': operation_type,
                    'maintenance_ticket': (
                        maintenance_ticket if operation_type == 'modify' else None
                    )
                })

            otp_code = pyotp.TOTP(
                admin_user.otp_secret, interval=30, digits=6, digest='sha1',
                name=admin_user.user_name, issuer='权限管理系统'
            ).now()

            for app_result in application_results:
                app_record = PermissionApplication.objects.get(
                    id=app_result['application_id']
                )
                app_record.verification_code_sent = True
                app_record.verification_code_sent_at = timezone.now()
                app_record.save()

        # 事务成功后发送钉钉通知（网络 I/O 在事务外，避免长时间持锁）
        title = "批量权限申请通知"
        server_info_list = [
            f"{app['username']}@{app['host']}:{app['port']}"
            for app in application_results
        ]
        server_info_text = "\n".join(server_info_list)

        content = (
            f"## 批量权限申请通知\n\n"
            f"- **申请人**: {user.user_name}\n"
            f"- **申请数量**: {len(applications)}\n"
            f"- **申请时长**: {duration}小时\n"
            f"- **操作类型**: {'修改' if operation_type == 'modify' else '查看'}\n"
        )
        if operation_type == 'modify':
            content += f"- **运维单号**: {maintenance_ticket}\n"
        content += (
            f"- **申请原因**: {reason}\n"
            f"- **申请时间**: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- **申请服务器列表**:\n{server_info_text}\n"
            f"- **管理员OTP验证码**: {otp_code}\n"
        )
        send_dingtalk_message(title, content)

        logger.info(
            f"用户 {user.user_name} 的批量申请已提交，共处理 {len(applications)} 个申请"
        )
        dingtalk_msg = (
            "已发送钉钉通知，请输入管理员OTP验证码"
            if DINGTALK_CONFIGURED
            else "请向管理员索取OTP验证码"
        )
        return JsonResponse({
            "status": "notify_sent",
            "message": dingtalk_msg,
            "applications": application_results,
            "password": unified_password,
            "dingtalk_configured": DINGTALK_CONFIGURED,
        })
    except json.JSONDecodeError:
        return JsonResponse(
            {"status": "error", "message": "请求数据格式错误"}, status=400
        )
    except Exception as e:
        logger.error(f"批量申请流程错误: {str(e)}", exc_info=True)
        return JsonResponse(
            {"status": "error", "message": f"申请失败: {str(e)}"}, status=500
        )


@login_required
@require_http_methods(["POST"])
def verify_bulk_otp(request):
    """验证批量申请的OTP令牌并更新服务器密码"""
    user = request.user

    try:
        data = json.loads(request.body)
        token_code = data.get("token_code", "")
        applications = data.get("applications", [])
        unified_password = data.get("password", "")
        # Bug7 修复：从请求中提取 operation_type 和 maintenance_ticket 并校验
        operation_type = data.get("operation_type", "view")
        maintenance_ticket = data.get("maintenance_ticket", "") or ""
        maintenance_ticket = maintenance_ticket.strip()

        if not applications:
            return JsonResponse(
                {"status": "error", "message": "未提供申请信息"}, status=400
            )
        if not unified_password:
            return JsonResponse(
                {"status": "error", "message": "未提供统一密码"}, status=400
            )

        # Bug7 修复：verify_bulk_otp 阶段也校验 operation_type
        if operation_type not in ['view', 'modify']:
            return JsonResponse(
                {"status": "error", "message": "无效的操作类型"}, status=400
            )
        if operation_type == 'modify':
            if not maintenance_ticket:
                return JsonResponse(
                    {"status": "error", "message": "修改操作必须提供运维单号"}, status=400
                )
            if not re.match(r'^\d+$', maintenance_ticket):
                return JsonResponse(
                    {"status": "error", "message": "运维单号只能包含数字"}, status=400
                )

        is_valid, error_msg, admin_user = verify_admin_otp(token_code)
        if not is_valid:
            return JsonResponse(
                {"status": "error", "message": error_msg},
                status=401 if error_msg == '令牌验证失败' else 400
            )

        # Bug6 修复：提前校验全部 duration
        for app in applications:
            duration = float(app.get("duration") or 0)
            if duration <= 0:
                return JsonResponse(
                    {"status": "error", "message": "申请时长必须大于0"}, status=400
                )

        application_results = []
        # Bug3 修复：整个批量更新包裹在事务中
        # 收集错误信息供最终报告
        errors = []

        with transaction.atomic():
            for app in applications:
                application_id = app.get("application_id")
                server_id = app.get("server_id")
                account_name = app.get("account_name", "").strip()
                host = app.get("host", "").strip()
                duration = float(app.get("duration") or 0)
                applicant_name = app.get("applicant", "").strip()

                # Bug2 修复：用 select_for_update 加行锁
                try:
                    server = ServerInfo.objects.select_for_update().get(id=server_id)
                except ServerInfo.DoesNotExist:
                    errors.append(f"服务器 {host} 不存在")
                    continue

                if server.username != account_name:
                    errors.append(
                        f"账户名 {account_name} 与服务器 {host} 配置不匹配"
                    )
                    continue

                # Bug2 修复：检查是否有其他批量申请已更新过此服务器
                now = timezone.now()
                if (server.password_expiration_time
                        and server.password_expiration_time > now
                        and server.generated_password):
                    # 已有批量申请的有效密码 → 复用，不重复 SSH 改密
                    logger.info(
                        f"服务器 {server.host} 已有批量密码，跳过 SSH 更新"
                    )
                    effective_password_used = server.generated_password
                    # 如果新申请时长更长，延长过期时间
                    applicant_expiration = now + timedelta(hours=duration)
                    if applicant_expiration > server.password_expiration_time:
                        server.password_expiration_time = applicant_expiration
                        server.current_duration = duration
                        server.save()
                        expiration_time = applicant_expiration
                    else:
                        expiration_time = server.password_expiration_time
                    update_ok = True
                elif (server.password_expiration_time
                      and server.password_expiration_time > now
                      and not server.generated_password):
                    # 有独立申请的有效密码（非批量）→ 也复用，避免覆盖
                    logger.info(
                        f"服务器 {server.host} 有独立申请的未过期密码，"
                        f"批量申请改用现有密码"
                    )
                    # 用现有密码替换统一密码（这台服务器密码不同于批量密码）
                    effective_password = server.get_password()
                    # 更新 DB 标记为共享
                    server.generated_password = effective_password
                    server.password_change_type = 'permission_apply'
                    applicant_expiration = now + timedelta(hours=duration)
                    if applicant_expiration > server.password_expiration_time:
                        server.password_expiration_time = applicant_expiration
                        server.current_duration = duration
                    server.save()
                    expiration_time = server.password_expiration_time
                    update_ok = True
                    # 覆盖：用服务器现有密码替代统一密码
                    effective_password_used = effective_password
                else:
                    # 无有效密码 → SSH 更新
                    update_ok = update_server_password(
                        server, unified_password, account_name
                    )
                    effective_password_used = unified_password

                if update_ok:
                    # 只在 SSH 更新成功时才写入新密码信息
                    if not (server.password_expiration_time
                            and server.password_expiration_time > now):
                        # 密码本就要过期或不存在 → 全新写入
                        expiration_time = now + timedelta(hours=duration)
                        server.password_expiration_time = expiration_time
                        server.current_duration = duration
                        server.last_password_change = now
                        server.generated_password = effective_password_used
                        server.password_change_type = 'permission_apply'
                        server.set_password(effective_password_used)
                        server.save()

                    # 更新申请记录
                    try:
                        app_record = PermissionApplication.objects.get(
                            id=application_id
                        )
                        app_record.status = 'approved'
                        app_record.approved_at = timezone.now()
                        if not app_record.batch_hosts:
                            all_hosts = [a.get("host", "") for a in applications]
                            app_record.batch_hosts = json.dumps(
                                all_hosts, ensure_ascii=False
                            )
                        app_record.save()
                    except PermissionApplication.DoesNotExist:
                        pass

                    application_results.append({
                        'host': server.host,
                        'port': server.port,
                        'username': account_name,
                        'applicant': applicant_name,
                        'expiration': (
                            expiration_time.strftime('%Y-%m-%d %H:%M:%S')
                        ),
                        'password': effective_password_used,
                    })
                    logger.info(
                        f"用户 {user.user_name} 的批量申请成功处理"
                        f"服务器 {server.host}"
                    )
                else:
                    errors.append(f"更新服务器 {server.host} 密码失败")

            # 如果有错误，回滚整个事务
            if errors:
                # 触发回滚：抛异常让 atomic() 块捕获
                raise _BatchPartialFailure(errors)

        logger.info(
            f"管理员 {user.user_name} 验证OTP成功，批量申请处理完成，"
            f"成功 {len(application_results)} 台"
        )
        return JsonResponse({
            "status": "success",
            "message": "批量申请成功",
            "passwords": application_results
        })

    except _BatchPartialFailure as e:
        logger.error(
            f"批量申请部分失败，已回滚: {e.errors}"
        )
        return JsonResponse({
            "status": "error",
            "message": "批量申请失败，未修改任何服务器。错误: " + "; ".join(e.errors)
        }, status=500)
    except json.JSONDecodeError:
        return JsonResponse(
            {"status": "error", "message": "请求数据格式错误"}, status=400
        )
    except Exception as e:
        logger.error(f"批量申请OTP验证失败: {str(e)}", exc_info=True)
        return JsonResponse(
            {"status": "error", "message": f"验证失败: {str(e)}"}, status=500
        )


class _BatchPartialFailure(Exception):
    """批量操作部分失败时抛出的内部异常，用于事务回滚"""
    def __init__(self, errors):
        self.errors = errors


@login_required
@require_http_methods(["POST"])
def get_batch_server_passwords(request):
    """批量获取服务器密码API（仅限管理员）"""
    admin_resp = admin_required(request.user)
    if admin_resp:
        return admin_resp

    try:
        data = json.loads(request.body)
        server_hosts = data.get('hosts', [])
        username = data.get('username', 'root')
        reason = data.get('reason', '').strip()

        if not server_hosts:
            return JsonResponse(
                {'status': 'error', 'message': '未提供主机列表'},
                status=400, json_dumps_params={'ensure_ascii': False}
            )
        if not reason:
            return JsonResponse(
                {'status': 'error', 'message': '请填写使用原因'},
                status=400, json_dumps_params={'ensure_ascii': False}
            )

        token_code = data.get('token_code', '').strip()
        is_valid, error_msg, _ = verify_admin_otp(token_code)
        if not is_valid:
            status_code = 401 if error_msg == '令牌验证失败' else 400
            return JsonResponse(
                {'status': 'error', 'message': error_msg},
                status=status_code, json_dumps_params={'ensure_ascii': False}
            )

        batch_hosts_json = json.dumps(server_hosts, ensure_ascii=False)
        now = timezone.now()

        # Bug1 修复：server FK 不允许 null，服务器不存在时只记录日志不创建记录
        failed_hosts = []
        for host in server_hosts:
            try:
                server = ServerInfo.objects.get(host=host, username=username)
                PermissionApplication.objects.create(
                    applicant=request.user, server=server,
                    account_name=username, reason=reason, duration=0,
                    status='approved', operation_type='batch',
                    approved_at=now, batch_hosts=batch_hosts_json
                )
            except ServerInfo.DoesNotExist:
                logger.warning(
                    f"批量获取密码: 服务器 {host} (用户:{username}) 不存在，跳过记录"
                )
                failed_hosts.append(host)

        server_passwords = []
        for host in server_hosts:
            try:
                server = ServerInfo.objects.get(host=host, username=username)
                decrypted_password = server.get_password()
                server_passwords.append({
                    'host': server.host, 'port': server.port,
                    'username': server.username,
                    'password': decrypted_password
                })
            except ServerInfo.DoesNotExist:
                server_passwords.append({
                    'host': host, 'error': '服务器不存在'
                })

        logger.info(
            f"管理员 {request.user.user_name} 批量获取了 {len(server_hosts)} "
            f"个服务器的密码，原因: {reason}"
        )
        return JsonResponse(
            {'status': 'success', 'servers': server_passwords},
            json_dumps_params={'ensure_ascii': False}
        )
    except json.JSONDecodeError:
        return JsonResponse(
            {'status': 'error', 'message': '请求数据格式错误'},
            status=400, json_dumps_params={'ensure_ascii': False}
        )
    except Exception as e:
        logger.error(f"批量获取服务器密码失败: {str(e)}", exc_info=True)
        return JsonResponse(
            {'status': 'error', 'message': f'获取密码失败: {str(e)}'},
            status=500, json_dumps_params={'ensure_ascii': False}
        )
