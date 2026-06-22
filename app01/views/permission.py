"""
权限申请核心视图：申请、OTP验证、密码过期检查
"""
import json
import logging
import re
import secrets
import string
from datetime import timedelta

import pyotp

from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.db import transaction

from app01.models import UserInfo, ServerInfo, PermissionApplication
from app01.views.common import verify_admin_otp, send_dingtalk_message, logger, DINGTALK_CONFIGURED
from app01.views.server import update_server_password

logger = logging.getLogger(__name__)


def generate_random_password(length=16):
    """生成安全的随机密码，排除影响识别的特殊字符"""
    exclude_chars = '$^`"\'\\|'
    allowed_punctuation = ''.join(c for c in string.punctuation if c not in exclude_chars)
    alphabet = string.ascii_letters + string.digits + allowed_punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def handle_concurrent_requests(server_id, duration, account_name, applicant_name):
    """
    处理并发请求，生成密码并设置过期时间

    策略：如果已有未过期的密码，新申请者共享同一密码，且若新申请者
    请求的时长超过当前剩余有效期，则自动延长过期时间。

    返回: (密码, 是否共享, 有效时长_小时, 过期时间) 或 None
    """
    try:
        logger.info(f"处理并发请求: server_id={server_id}, duration={duration}小时, "
                     f"account={account_name}, applicant={applicant_name}")

        with transaction.atomic():
            server = ServerInfo.objects.select_for_update().get(id=server_id)
            now = timezone.now()
            applicant_expiration = now + timedelta(hours=duration)

            # --- 已有未过期密码：共享模式 ---
            if server.password_expiration_time and server.password_expiration_time > now:
                current_password = (server.generated_password
                                    if server.generated_password
                                    else server.get_password())

                # 如果新申请者要求的过期时间比现有更晚，则延长
                if applicant_expiration > server.password_expiration_time:
                    old_expiration = server.password_expiration_time
                    server.password_expiration_time = applicant_expiration
                    server.current_duration = duration
                    server.save()

                    logger.info(
                        f"服务器 {server.host} 密码有效期已延长: "
                        f"{old_expiration.strftime('%H:%M')} → "
                        f"{applicant_expiration.strftime('%H:%M')}, "
                        f"申请人: {applicant_name}"
                    )
                    return (current_password, True, duration, applicant_expiration)
                else:
                    logger.info(
                        f"服务器 {server.host} 已有未过期密码，"
                        f"新申请人 {applicant_name} 的时长未超过当前有效期，不延长"
                    )
                    return (current_password, True,
                            server.current_duration,
                            server.password_expiration_time)

            # --- 无有效密码：生成新密码 ---
            new_password = generate_random_password()

            if update_server_password(server, new_password, account_name):
                server.password_expiration_time = applicant_expiration
                server.current_duration = duration
                server.last_password_change = now
                server.generated_password = None
                server.password_change_type = 'permission_apply'
                server.set_password(new_password)
                server.save()

                logger.info(f"服务器 {server.host} 密码处理成功（新密码）")
                return (new_password, False, duration, applicant_expiration)
            else:
                logger.error(f"更新服务器 {server.host} 密码失败")
                return None

    except ServerInfo.DoesNotExist:
        logger.error(f"服务器ID {server_id} 不存在")
        return None
    except Exception as e:
        logger.error(f"处理服务器 {server_id} 请求时出错: {str(e)}", exc_info=True)
        return None


def check_expired_passwords():
    """检查并更新已过期的密码（定时任务调用）"""
    try:
        logger = logging.getLogger(__name__)
        now = timezone.now()

        from server_management.config import Config
        password_expire_days = Config.PASSWORD_EXPIRE_DAYS

        expired_servers = ServerInfo.objects.filter(
            password_expiration_time__lte=now
        ).exclude(password_expiration_time__isnull=True)

        expire_threshold = now - timedelta(days=password_expire_days)
        auto_expired_servers = ServerInfo.objects.filter(
            last_password_change__lte=expire_threshold
        )

        updated_count = 0
        if expired_servers.exists() or auto_expired_servers.exists():
            logger.info("开始检查服务器密码过期情况")

        for server in expired_servers:
            try:
                new_password = generate_random_password()
                if update_server_password(server, new_password, server.username):
                    server.password_expiration_time = None
                    server.current_duration = 0
                    server.generated_password = None
                    server.last_password_change = now
                    server.password_change_type = 'permission_apply'
                    server.set_password(new_password)
                    server.save()
                    updated_count += 1
                    logger.info(f"服务器 {server.host} 的权限申请密码已过期并更新成功")
                else:
                    logger.error(f"服务器 {server.host} 密码更新失败")
            except Exception as e:
                logger.error(f"更新服务器 {server.host} 密码时出错: {str(e)}", exc_info=True)

        for server in auto_expired_servers:
            try:
                if server in expired_servers:
                    continue
                new_password = generate_random_password()
                if update_server_password(server, new_password, server.username):
                    server.last_password_change = now
                    server.password_change_type = 'auto_expired'
                    server.set_password(new_password)
                    server.save()
                    updated_count += 1
                    logger.info(f"服务器 {server.host} 的密码因长时间未修改而自动更新")
                else:
                    logger.error(f"服务器 {server.host} 密码更新失败")
            except Exception as e:
                logger.error(f"更新服务器 {server.host} 密码时出错: {str(e)}", exc_info=True)

        if updated_count > 0:
            logger.info(f"过期密码检查完成，共更新 {updated_count} 个服务器")
        elif expired_servers.exists() or auto_expired_servers.exists():
            logger.info("过期密码检查完成，无需更新")

        return updated_count
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"检查过期密码时出错: {str(e)}", exc_info=True)
        return 0


@login_required
@require_http_methods(["POST"])
def apply_permission(request):
    """用户权限申请：先发钉钉通知，再要求OTP验证"""
    import json
    user = request.user

    try:
        data = json.loads(request.body)
        server_id = int(data.get("server_id"))
        account_name = data.get("account_name", "").strip()
        duration = float(data.get("duration", 0))
        reason = data.get("reason", "").strip()
        operation_type = data.get("operation_type", "view")
        maintenance_ticket = data.get("maintenance_ticket", "") or ""
        maintenance_ticket = maintenance_ticket.strip()

        if not account_name or duration <= 0:
            return JsonResponse({"status": "error", "message": "账户名或时长无效"}, status=400)
        if not reason:
            return JsonResponse({"status": "error", "message": "请填写申请原因"}, status=400)
        if operation_type not in ['view', 'modify']:
            return JsonResponse({"status": "error", "message": "无效的操作类型"}, status=400)
        if operation_type == 'modify':
            if not maintenance_ticket:
                return JsonResponse({"status": "error", "message": "修改操作必须提供运维单号"}, status=400)
            if not re.match(r'^\d+$', maintenance_ticket):
                return JsonResponse({"status": "error", "message": "运维单号只能包含数字"}, status=400)

        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            return JsonResponse({"status": "error", "message": "服务器不存在"}, status=404)

        if server.username != account_name:
            return JsonResponse({"status": "error", "message": "账户名与服务器配置不匹配"}, status=400)

        application = PermissionApplication.objects.create(
            applicant=user, server=server, account_name=account_name,
            reason=reason, duration=duration, status='verification_pending',
            operation_type=operation_type,
            maintenance_ticket=maintenance_ticket if operation_type == 'modify' else None
        )

        admin_user = UserInfo.objects.filter(
            is_superuser=True, otp_secret__isnull=False, otp_active=True
        ).first()
        if not admin_user:
            application.status = 'verification_failed'
            application.save()
            return JsonResponse({"status": "error", "message": "未找到已激活的管理员令牌"}, status=400)

        totp = pyotp.TOTP(admin_user.otp_secret, interval=30, digits=6, digest='sha1',
                          name=admin_user.user_name, issuer='权限管理系统')
        otp_code = totp.now()

        application.verification_code_sent = True
        application.verification_code_sent_at = timezone.now()
        application.save()

        title = "权限申请通知"
        content = (
            f"## 权限申请通知\n\n"
            f"- **申请人**: {user.user_name}\n"
            f"- **服务器**: {server.host}:{server.port}\n"
            f"- **账户名**: {account_name}\n"
            f"- **申请时长**: {duration}小时\n"
            f"- **操作类型**: {'修改' if operation_type == 'modify' else '查看'}\n"
        )
        if operation_type == 'modify':
            content += f"- **运维单号**: {maintenance_ticket}\n"
        content += (
            f"- **申请原因**: {reason}\n"
            f"- **申请时间**: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- **管理员OTP验证码**: {otp_code}\n"
        )
        send_dingtalk_message(title, content)

        logger.info(f"权限申请已提交: 用户={user.user_name}, 服务器={server.host}, 时长={duration}小时")
        dingtalk_msg = (
            "已发送钉钉通知，请输入管理员OTP验证码"
            if DINGTALK_CONFIGURED
            else "请向管理员索取OTP验证码"
        )
        return JsonResponse({
            "status": "notify_sent",
            "message": dingtalk_msg,
            "application_id": application.id,
            "dingtalk_configured": DINGTALK_CONFIGURED,
        })
    except Exception as e:
        logger.error(f"申请流程错误: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"申请失败: {str(e)}"}, status=500)


@login_required
@require_http_methods(["POST"])
def verify_otp(request):
    """验证OTP令牌并返回服务器密码"""
    import json
    user = request.user

    try:
        data = json.loads(request.body)
        token_code = data.get("token_code", "")
        server_id = data.get("server_id")
        account_name = data.get("account_name", "").strip()
        duration = float(data.get("duration", 0))
        application_id = data.get("application_id")

        logger.debug(f"收到OTP验证请求: user={user.user_name}, server_id={server_id}")

        is_valid, error_msg, admin_user = verify_admin_otp(token_code)
        if not is_valid:
            # 尝试更新申请状态
            if application_id:
                try:
                    app = PermissionApplication.objects.get(id=application_id)
                    app.status = 'verification_failed'
                    app.verification_attempts += 1
                    app.last_verification_attempt = timezone.now()
                    app.save()
                except PermissionApplication.DoesNotExist:
                    pass
            return JsonResponse({"status": "error", "message": error_msg},
                                status=401 if error_msg == '令牌验证失败' else 400)

        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            return JsonResponse({"status": "error", "message": "服务器不存在"}, status=404)

        # root 用户可以修改任意账号密码，非 root 用户只能修改自身密码
        if server.username != 'root' and server.username != account_name:
            return JsonResponse({"status": "error", "message": "账号不匹配，请联系管理员"}, status=400)

        result = handle_concurrent_requests(server_id, duration, account_name, user.user_name)
        if result is None:
            return JsonResponse({"status": "error", "message": "密码处理失败"}, status=500)

        password, is_shared, original_duration, expiration_time = result

        if application_id:
            try:
                app = PermissionApplication.objects.get(id=application_id)
                app.status = 'approved'
                app.approved_at = timezone.now()
                app.verification_attempts += 1
                app.last_verification_attempt = timezone.now()
                app.save()
            except PermissionApplication.DoesNotExist:
                pass

        response_data = {
            "status": "success",
            "server_info": {
                "host": server.host, "port": server.port,
                "username": account_name, "password": password,
                "expiration": expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                "applicant": user.user_name,
                "application_time": timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                "is_shared": is_shared,
                "effective_duration_hours": original_duration,
            }
        }
        if is_shared:
            response_data["message"] = (
                f"您正在使用共享密码，"
                f"有效期至 {expiration_time.strftime('%Y-%m-%d %H:%M:%S')}"
                f"（共 {original_duration} 小时）"
            )

        logger.info(f"OTP验证成功，返回服务器信息: user={user.user_name}, server={server.host}")
        return JsonResponse(response_data)
    except Exception as e:
        logger.error(f"OTP验证失败: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"验证失败: {str(e)}"}, status=500)
