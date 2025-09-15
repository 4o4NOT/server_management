import logging
import re
import json
import pyotp
import qrcode
import requests
import paramiko
import secrets
import string
import hashlib
from datetime import datetime, timedelta
from io import BytesIO
from base64 import b64encode

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import login as auth_login, authenticate, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from django.db import transaction
from django.views.decorators.http import require_http_methods, require_GET
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import UserInfo, ServerInfo, PermissionApplication
from server_management.config import Config


# 配置日志记录器，用于记录系统运行过程中的信息、警告和错误
logger = logging.getLogger(__name__)

# 尝试从配置模块导入配置，如果失败则使用默认值
try:
    from server_management.config import Config
    DINGTALK_WEBHOOK_URL = Config.DINGTALK_WEBHOOK_URL
    logger.info(f"已从配置文件加载钉钉Webhook URL: {DINGTALK_WEBHOOK_URL[:50]}...")
except ImportError as e:
    logger.warning(f"无法从配置模块加载钉钉Webhook URL，使用默认值: {e}")
    DINGTALK_WEBHOOK_URL = "https://oapi.dingtalk.com/robot/send?access_token=0afe9334cdfe89d2fdcd1eb9e761cb11212883a9c40588b0bc6972bb50a5ec98"


def send_dingtalk_message(title, content):
    """
    发送钉钉消息
    :param title: 消息标题
    :param content: 消息内容
    """
    try:
        headers = {'Content-Type': 'application/json'}
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": content
            }
        }
        response = requests.post(DINGTALK_WEBHOOK_URL, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            logger.info("钉钉消息发送成功")
        else:
            logger.error(f"钉钉消息发送失败，状态码: {response.status_code}")
    except Exception as e:
        logger.error(f"发送钉钉消息时发生错误: {str(e)}")


# 自定义认证后端
class CustomModelBackend(ModelBackend):
    """自定义认证后端，支持用户名或手机号登录"""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        重写认证方法，支持使用用户名或手机号进行登录
        :param request: HTTP请求对象
        :param username: 用户名或手机号
        :param password: 密码
        :param kwargs: 其他参数
        :return: 认证成功的用户对象或None
        """
        try:
            # 尝试通过用户名查找用户
            user = UserInfo.objects.get(user_name=username)
        except UserInfo.DoesNotExist:
            try:
                # 尝试通过手机号查找用户
                user = UserInfo.objects.get(phone=username)
            except UserInfo.DoesNotExist:
                return None

        # 验证密码
        if user.check_password(password):
            return user
        return None


# JWT登录装饰器
def jwt_login_required(view_func):
    """自定义JWT登录装饰器，用于保护需要认证的视图"""

    def _wrapped_view(request, *args, **kwargs):
        """
        包装函数，检查用户是否已认证
        :param request: HTTP请求对象
        :param args: 位置参数
        :param kwargs: 关键字参数
        :return: 视图函数返回结果或重定向到登录页
        """
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'status': 'error',
                    'message': '未认证'
                }, status=401)
            return redirect(reverse('login'))
        return view_func(request, *args, **kwargs)

    return _wrapped_view


# 首页视图
@login_required
def index(request):
    """首页视图"""
    user = request.user
    logger.info(f"用户 {user.user_name} 访问首页")

    # 获取服务器数据，用于自动完成
    servers = list(ServerInfo.objects.all().values('id', 'host', 'port', 'username', 'description'))

    # 获取时长选项
    duration_options = Config.get_duration_options()

    # 获取密码显示模式配置
    password_display_mode = getattr(Config, 'PASSWORD_DISPLAY_MODE', 'auto_copy')

    # 添加调试日志
    logger.info(f"密码显示模式配置: {password_display_mode}")

    context = {
        'servers': json.dumps(servers),
        'duration_options': duration_options,
        'password_display_mode': password_display_mode,
    }

    return render(request, 'index.html', context)

# 登录视图
def user_login(request):
    """登录视图，处理用户登录请求"""
    logger.debug("收到登录请求，方法: %s", request.method)

    if request.method == 'GET':
        logger.debug("返回登录页面")
        return render(request, 'login.html')

    if request.method == 'POST':
        identifier = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        # 验证用户名和密码
        try:
            # 用户名查询
            user = UserInfo.objects.get(user_name=identifier)
        except UserInfo.DoesNotExist:
            try:
                # 手机号查询
                user = UserInfo.objects.get(phone=identifier)
            except UserInfo.DoesNotExist:
                return JsonResponse({
                    'status': 'error',
                    'message': '用户名或密码不正确'
                })

        # 验证密码
        if not user.check_password(password):
            return JsonResponse({
                'status': 'error',
                'message': '用户名或密码不正确'
            })
        # 检查用户是否被禁用
        if not user.is_active:
            logger.warning(f"尝试登录的被禁用用户: {user.user_name}")
            return JsonResponse({
                'status': 'error',
                'message': '账户已被禁用，请联系管理员'
            })

        # 更新最后登录时间
        user.last_login = timezone.now()
        user.save()

        # 使用自定义认证后端登录用户
        backend = CustomModelBackend()
        authenticated_user = backend.authenticate(request, username=identifier, password=password)

        if authenticated_user is not None:
            # 明确指定认证后端
            auth_login(request, authenticated_user, backend='app01.views.CustomModelBackend')
        else:
            logger.error("认证后端返回的用户为空")
            return JsonResponse({
                'status': 'error',
                'message': '认证失败'
            })

        # 生成JWT令牌
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # 创建响应对象
        response = JsonResponse({
            'status': 'success',
            'message': '登录成功',
            'redirect_url': '/index/'
        })

        # 设置访问令牌cookie，使用秒数而不是timedelta对象
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            max_age=int(timedelta(hours=3).total_seconds()),  # 3小时有效期
            samesite='Lax',
            secure=settings.SECURE_COOKIE
        )

        return response
    return None


# 登出视图
def user_logout(request):
    """登出视图，处理用户登出请求"""
    logger.info("用户登出")

    try:
        # 使用Django认证系统登出
        auth_logout(request)

        # 创建重定向到登录页的响应
        response = redirect(reverse('login'))

        # 删除访问令牌cookie
        response.delete_cookie('access_token', path='/', domain=settings.SESSION_COOKIE_DOMAIN)

        return response
    except Exception as e:
        logger.error(f"登出过程中发生错误: {str(e)}")
        return redirect(reverse('login'))


# 注册视图
def register(request):
    """注册视图，处理用户注册请求"""
    logger.debug("收到注册请求，方法: %s", request.method)

    if request.method == 'GET':
        return render(request, 'register.html')

    if request.method == 'POST':
        # 获取表单数据
        username = request.POST.get('username', '').strip()
        phone = request.POST.get('phone', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirmPassword', '')

        # 验证密码是否匹配
        if password != confirm_password:
            return JsonResponse({
                'status': 'error',
                'message': '两次输入的密码不一致'
            })

        # 验证用户名（2-4个汉字）
        if not re.match(r'^[\u4e00-\u9fa5]{2,4}$', username):
            return JsonResponse({
                'status': 'error',
                'message': '请输入2-4个汉字的中文姓名'
            })

        # 验证手机号 (11位数字)
        if not re.match(r'^\d{11}$', phone):
            return JsonResponse({
                'status': 'error',
                'message': '手机号格式不正确'
            })

        # 验证密码复杂性
        if len(password) < 8:
            return JsonResponse({
                'status': 'error',
                'message': '密码长度至少为8个字符'
            })
        elif not re.search(r'[A-Z]', password):  # 检查大写字母
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个大写字母'
            })
        elif not re.search(r'[a-z]', password):  # 检查小写字母
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个小写字母'
            })
        elif not re.search(r'[0-9]', password):  # 检查数字
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个数字'
            })
        elif not re.search(r'[^A-Za-z0-9]', password):  # 检查特殊字符
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个特殊字符'
            })

        # 检查手机号是否已存在
        if UserInfo.objects.filter(phone=phone).exists():
            return JsonResponse({
                'status': 'error',
                'message': '该手机号已被注册'
            })

        # 检查用户名是否已存在
        if UserInfo.objects.filter(user_name=username).exists():
            return JsonResponse({
                'status': 'error',
                'message': '该用户名已被使用'
            })

        try:
            # 创建新用户
            user = UserInfo(user_name=username, phone=phone)
            user.set_password(password)
            user.save()

            return JsonResponse({
                'status': 'success',
                'message': '注册成功！'
            })
        except Exception as e:
            logger.error(f"注册失败: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': f'注册失败: {str(e)}'
            })
    return None


# 用户管理视图
@login_required
def user_management(request):
    """用户管理视图，管理员可以查看和管理所有用户"""
    # 权限检查
    if not request.user.is_superuser:
        return render(request, '403.html', status=403)

    # 处理搜索和过滤
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', 'all')  # 'all', 'active', 'inactive'
    admin_filter = request.GET.get('admin', 'all')  # 'all', 'admin', 'regular'

    # 构建查询条件
    users = UserInfo.objects.all()
    if search_query:
        users = users.filter(
            Q(user_name__icontains=search_query) | Q(phone__icontains=search_query)
        )
    if status_filter != 'all':
        users = users.filter(is_active=(status_filter == 'active'))
    if admin_filter != 'all':
        users = users.filter(is_superuser=(admin_filter == 'admin'))

    # 统计信息
    total = users.count()
    active = users.filter(is_active=True).count()
    inactive = users.filter(is_active=False).count()
    admin = users.filter(is_superuser=True).count()
    regular = total - admin

    stats = {
        'total': total,
        'active': active,
        'inactive': inactive,
        'admin': admin,
        'regular': regular
    }

    # 分页
    # 添加排序字段（按ID或注册时间排序）
    users = UserInfo.objects.all().order_by('-date_joined')  # 按注册时间降序排序
    page = request.GET.get('page', 1)
    paginator = Paginator(users, 10)  # 每页10条
    # 添加排序字段（按ID或注册时间排序）
    users = UserInfo.objects.all().order_by('-date_joined')  # 按注册时间降序排序
    try:
        users_page = paginator.page(page)
    except EmptyPage:
        users_page = paginator.page(paginator.num_pages)
    except Exception:
        users_page = paginator.page(1)

    # 传递给模板
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
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        
        # 不能删除其他管理员
        if user.is_superuser:
            return JsonResponse({
                'status': 'error',
                'message': '不能删除管理员用户'
            }, status=403)
            
        # 不能删除自己
        if user.id == request.user.id:
            return JsonResponse({
                'status': 'error',
                'message': '不能删除当前登录的用户'
            }, status=400)
            
        user.delete()
        return JsonResponse({
            'status': 'success',
            'message': '用户删除成功'
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)
    except Exception as e:
        logger.error(f"删除用户失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': f'删除失败: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def toggle_user_active(request, user_id):
    """切换用户激活状态（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        
        # 管理员不能操作其他管理员账户
        if user.is_superuser and user.id != request.user.id:
            return JsonResponse({
                'status': 'error',
                'message': '不能操作其他管理员账户'
            }, status=403)

        # 不能禁用自己
        if user.id == request.user.id:
            return JsonResponse({
                'status': 'error',
                'message': '不能禁用当前登录的用户'
            }, status=400)

        # 更新状态
        user.is_active = not user.is_active
        user.save()

        # 获取当前状态和将要设置的状态
        current_status = "已启用" if user.is_active else "已禁用"
        new_status = "禁用" if user.is_active else "启用"

        return JsonResponse({
            'status': 'success',
            'message': f'用户已{new_status}',  # 动态状态提示
            'is_active': user.is_active,  # 返回当前激活状态
            'action': new_status          # 返回执行的操作
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)
    except Exception as e:
        logger.error(f"切换用户状态失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': f'状态更新失败: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def reset_password(request, user_id):
    """重置用户密码（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        
        # 不能重置其他管理员的密码
        if user.is_superuser and user.id != request.user.id:
            return JsonResponse({
                'status': 'error',
                'message': '不能重置其他管理员的密码'
            }, status=403)
        
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_new_password')

        # 验证密码
        if not new_password or new_password != confirm_password:
            return JsonResponse({
                'status': 'error',
                'message': '两次输入的密码不一致'
            })

        logger.info(f"管理员 {request.user.user_name} 重置用户 {user.user_name} 的密码")

        # 设置新密码
        user.set_password(new_password)
        user.save()

        return JsonResponse({
            'status': 'success',
            'message': '密码重置成功'
        })

    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)
    except Exception as e:
        logger.error(f"重置密码失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': f'重置密码失败: {str(e)}'
        }, status=500)

# 管理员OTP管理
@login_required
def otp_management(request):
    """OTP验证管理视图（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    user = request.user

    # 生成或获取OTP密钥
    if not user.otp_secret:
        # 生成新的OTP密钥
        user.otp_secret = pyotp.random_base32()
        user.save()

    # 生成OTP URI，设置窗口期为2
    totp = pyotp.totp.TOTP(user.otp_secret, interval=30, digits=6, digest=hashlib.sha1)
    otp_uri = totp.provisioning_uri(
        name=user.user_name,
        issuer_name="权限管理系统"
    )

    # 生成二维码图片
    img = qrcode.make(otp_uri)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = b64encode(buffer.getvalue()).decode()

    # 在页面上显示二维码
    return render(request, 'otp_management.html', {
        'qr_code': img_str,
        'otp_secret': user.otp_secret
    })


# 服务器管理
@login_required
def server_management(request):
    """服务器管理视图（仅限管理员）"""
    if not request.user.is_superuser:
        # 处理API请求的响应
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'message': '权限不足'
            }, status=403)
        return render(request, '403.html', status=403)

    # 处理API请求（前端JavaScript发起的请求）
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            # 获取所有服务器信息
            servers = ServerInfo.objects.all()

            # 构建响应数据
            server_list = []
            for server in servers:
                server_list.append({
                    'id': server.id,
                    'target_host': server.host,
                    'target_port': server.port,
                    'username': server.username,
                    'password': '******',  # 不直接返回密码
                    'description': server.description or ''
                })

            return JsonResponse({
                'status': 'success',
                'data': server_list
            })
        except Exception as e:
            logger.error(f"获取服务器列表失败: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': '获取服务器列表失败'
            }, status=500)

    # 处理普通页面请求
    servers = ServerInfo.objects.all()
    return render(request, 'server_management.html', {'servers': servers})


# 获取用户令牌信息
@login_required
@require_http_methods(["GET"])
def get_user_token(request, user_id):
    """获取指定用户的令牌信息（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        return JsonResponse({
            'status': 'success',
            'otp_secret': user.otp_secret,
            'otp_active': user.otp_active
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)


# 生成用户令牌
@login_required
@require_http_methods(["POST"])
def generate_token(request, user_id):
    """为指定用户生成新的令牌（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        # 检查系统中是否已存在其他用户的令牌
        existing_token_user = UserInfo.objects.filter(otp_secret__isnull=False).exclude(id=user_id).first()
        if existing_token_user:
            return JsonResponse({
                'status': 'error',
                'message': f'系统中已存在令牌（属于用户：{existing_token_user.user_name}），不允许多个令牌'
            }, status=400)
        
        user = UserInfo.objects.get(id=user_id)
        # 生成新的OTP密钥
        user.otp_secret = pyotp.random_base32()
        user.otp_active = False
        user.save()

        return JsonResponse({
            'status': 'success',
            'message': '令牌生成成功',
            'otp_secret': user.otp_secret
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)


# 验证用户令牌
@login_required
@require_http_methods(["POST"])
def verify_token(request, user_id):
    """验证用户输入的令牌验证码（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        token_code = request.POST.get('token_code', '')

        # 验证OTP，设置窗口期为2
        totp = pyotp.TOTP(user.otp_secret, interval=30, digits=6, digest='sha1', name=user.user_name, issuer='权限管理系统')
        if totp.verify(token_code, valid_window=2):
            # 验证成功，标记OTP已激活
            user.otp_active = True
            user.save()
            return JsonResponse({
                'status': 'success',
                'message': '令牌验证成功，已激活！'
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': '令牌验证失败，请重试'
            })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)


# 重置用户令牌
@login_required
@require_http_methods(["POST"])
def reset_token(request, user_id):
    """重置指定用户的令牌（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        user = UserInfo.objects.get(id=user_id)
        # 清除令牌信息
        user.otp_secret = None
        user.otp_active = False
        user.save()

        return JsonResponse({
            'status': 'success',
            'message': '令牌已重置，用户需要重新绑定'
        })
    except UserInfo.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': '用户不存在'
        }, status=404)


# 添加服务器
@login_required
@require_http_methods(["POST"])
def add_server(request):
    """
    添加服务器（仅限管理员）
    支持JSON和表单两种数据格式
    """
    logger.debug("收到添加服务器请求")
    logger.debug(f"请求方法: {request.method}")
    logger.debug(f"请求内容类型: {request.content_type}")
    logger.debug(f"请求体大小: {len(request.body)} 字节")
    logger.debug(f"请求体内容: {request.body}")
    
    if not request.user.is_superuser:
        response = JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)
        response['Server'] = ''  # 移除Server头信息
        return response

    try:
        # 根据内容类型处理请求数据
        if request.content_type and 'application/json' in request.content_type:
            # 处理JSON数据
            logger.debug("处理JSON格式数据")
            try:
                data = json.loads(request.body)
                logger.debug(f"解析后的JSON数据: {data}")
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析失败: {str(e)}")
                response = JsonResponse({
                    'status': 'error',
                    'message': f'JSON数据格式错误: {str(e)}'
                }, status=400)
                response['Server'] = ''  # 移除Server头信息
                return response
        elif request.content_type and 'application/x-www-form-urlencoded' in request.content_type:
            # 处理表单数据
            logger.debug("处理表单数据")
            try:
                # 解析表单数据
                from django.http import QueryDict
                form_data = QueryDict(request.body.decode('utf-8'))
                data = {
                    'host': form_data.get('host', ''),
                    'port': form_data.get('port', '22'),
                    'username': form_data.get('username', ''),
                    'password': form_data.get('password', ''),
                    'description': form_data.get('description', '')
                }
                # 端口需要转换为整数
                try:
                    data['port'] = int(data['port'])
                except (ValueError, TypeError):
                    data['port'] = 22
                logger.debug(f"解析后的表单数据: {data}")
            except Exception as e:
                logger.error(f"表单数据解析失败: {str(e)}")
                response = JsonResponse({
                    'status': 'error',
                    'message': f'表单数据解析失败: {str(e)}'
                }, status=400)
                response['Server'] = ''  # 移除Server头信息
                return response
        else:
            logger.error(f"不支持的内容类型: {request.content_type}")
            response = JsonResponse({
                'status': 'error',
                'message': f'不支持的内容类型: {request.content_type}'
            }, status=400)
            response['Server'] = ''  # 移除Server头信息
            return response

        host = data.get('host')
        port = data.get('port', 22)
        username = data.get('username')
        password = data.get('password')
        description = data.get('description', '')

        # 验证输入
        if not host or not username or not password:
            response = JsonResponse({
                'status': 'error',
                'message': '主机地址、用户名和密码不能为空'
            }, status=400)
            response['Server'] = ''  # 移除Server头信息
            return response
        
        # 检查主机地址和用户组合是否已存在
        if ServerInfo.objects.filter(host=host, username=username).exists():
            response = JsonResponse({
                'status': 'error',
                'message': '该主机地址和用户名组合已存在'
            }, status=400)
            response['Server'] = ''  # 移除Server头信息
            return response

        # SSH连接测试
        ssh_test_result = test_ssh_connection(host, port, username, password)
        if not ssh_test_result['success']:
            response = JsonResponse({
                'status': 'error',
                'message': f'SSH连接测试失败: {ssh_test_result["message"]}'
            }, status=400)
            response['Server'] = ''  # 移除Server头信息
            return response

        # 创建服务器记录
        server = ServerInfo(
            host=host,
            port=port,
            username=username,
            description=description,
            last_password_change=timezone.now()
        )
        # 使用加密方法设置密码
        server.set_password(password)
        server.save()
        
        logger.info(f"管理员 {request.user.user_name} 添加了服务器 {host}:{port}")

        response = JsonResponse({
            'status': 'success',
            'message': '服务器添加成功',
            'server_id': server.id
        })
        response['Server'] = ''  # 移除Server头信息
        return response
    except Exception as e:
        logger.error(f"添加服务器失败: {str(e)}", exc_info=True)
        response = JsonResponse({
            'status': 'error',
            'message': f'服务器添加失败: {str(e)}'
        }, status=400)
        response['Server'] = ''  # 移除Server头信息
        return response

def test_ssh_connection(host, port, username, password):
    """
    测试SSH连接
    
    参数:
        host: 主机地址
        port: 端口
        username: 用户名
        password: 密码
    
    返回:
        dict: 包含success和message的字典
    """
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 尝试连接
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False
        )
        
        # 执行简单命令测试连接
        stdin, stdout, stderr = ssh.exec_command('echo "SSH connection test successful"')
        exit_status = stdout.channel.recv_exit_status()
        
        ssh.close()
        
        if exit_status == 0:
            return {
                'success': True,
                'message': 'SSH连接测试成功'
            }
        else:
            return {
                'success': False,
                'message': 'SSH命令执行失败'
            }
            
    except paramiko.AuthenticationException:
        if ssh:
            ssh.close()
        return {
            'success': False,
            'message': 'SSH认证失败，请检查用户名和密码'
        }
    except paramiko.SSHException as e:
        if ssh:
            ssh.close()
        return {
            'success': False,
            'message': f'SSH连接异常: {str(e)}'
        }
    except Exception as e:
        if ssh:
            ssh.close()
        return {
            'success': False,
            'message': f'连接失败: {str(e)}'
        }

@login_required
@require_http_methods(["POST"])
def update_server(request, server_id):
    """更新服务器信息（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        server = ServerInfo.objects.get(id=server_id)
        data = json.loads(request.body)

        # 记录变更前的信息
        old_host = server.host
        old_username = server.username

        # 更新字段
        server.host = data.get('host', server.host)
        server.port = data.get('port', server.port)
        server.username = data.get('username', server.username)
        server.description = data.get('description', server.description)

        # 如果提供了新密码则更新
        if 'password' in data and data['password']:
            server.set_password(data['password'])

        server.save()

        logger.info(f"管理员 {request.user.user_name} 更新了服务器 {old_host} -> {server.host}")

        response = JsonResponse({
            'status': 'success',
            'message': '服务器更新成功'
        })
        response['Server'] = ''  # 移除Server头信息
        return response
    except ServerInfo.DoesNotExist:
        response = JsonResponse({
            'status': 'error',
            'message': '服务器不存在'
        }, status=404)
        response['Server'] = ''  # 移除Server头信息
        return response
    except Exception as e:
        logger.error(f"更新服务器失败: {str(e)}")
        response = JsonResponse({
            'status': 'error',
            'message': f'更新失败: {str(e)}'
        }, status=500)
        response['Server'] = ''  # 移除Server头信息
        return response


# 删除服务器API
@login_required
@require_http_methods(["POST"])
def delete_server(request, server_id):
    """删除服务器（仅限管理员）"""
    if not request.user.is_superuser:
        response = JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)
        response['Server'] = ''  # 移除Server头信息
        return response

    try:
        server = ServerInfo.objects.get(id=server_id)
        server.delete()
        response = JsonResponse({
            'status': 'success',
            'message': '服务器删除成功'
        })
        response['Server'] = ''  # 移除Server头信息
        return response
    except ServerInfo.DoesNotExist:
        response = JsonResponse({
            'status': 'error',
            'message': '服务器不存在'
        }, status=404)
        response['Server'] = ''  # 移除Server头信息
        return response
    except Exception as e:
        logger.error(f"删除服务器失败: {str(e)}")
        response = JsonResponse({
            'status': 'error',
            'message': f'删除失败: {str(e)}'
        }, status=500)
        response['Server'] = ''  # 移除Server头信息
        return response


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
        duration = float(data.get("duration", 0))  # 改为float以支持小数
        reason = data.get("reason", "").strip()

        if not account_name or duration <= 0:
            return JsonResponse({"status": "error", "message": "账户名或时长无效"}, status=400)
        
        if not reason:
            return JsonResponse({"status": "error", "message": "请填写申请原因"}, status=400)

        # 找到服务器
        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            return JsonResponse({"status": "error", "message": "服务器不存在"}, status=404)

        # 验证账户名是否与服务器关联
        if server.username != account_name:
            return JsonResponse({"status": "error", "message": "账户名与服务器配置不匹配"}, status=400)

        # 创建申请记录
        application = PermissionApplication.objects.create(
            applicant=user,
            server=server,
            account_name=account_name,
            reason=reason,
            duration=duration,
            status='verification_pending'  # 等待验证
        )

        # 找已激活的管理员令牌
        admin_user = UserInfo.objects.filter(is_superuser=True, otp_secret__isnull=False, otp_active=True).first()
        if not admin_user:
            # 更新申请状态为验证失败
            application.status = 'verification_failed'
            application.save()
            return JsonResponse({"status": "error", "message": "未找到已激活的管理员令牌"}, status=400)

        totp = pyotp.TOTP(admin_user.otp_secret, interval=30, digits=6, digest='sha1', 
                          name=admin_user.user_name, issuer='权限管理系统')
        otp_code = totp.now()

        # 更新申请记录，标记验证码已发送
        application.verification_code_sent = True
        application.verification_code_sent_at = timezone.now()
        application.save()

        # 发送钉钉通知
        title = "权限申请通知"
        content = (
            f"## 权限申请通知\n\n"
            f"- **申请人**: {user.user_name}\n"
            f"- **服务器**: {server.host}:{server.port}\n"
            f"- **账户名**: {account_name}\n"
            f"- **申请时长**: {duration}小时\n"
            f"- **申请原因**: {reason}\n"
            f"- **申请时间**: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- **管理员OTP验证码**: {otp_code}\n"
        )
        send_dingtalk_message(title, content)

        logger.info(f"已发送钉钉通知，等待用户输入OTP。申请人: {user.user_name}, 服务器: {server.host}")

        return JsonResponse({
            "status": "notify_sent",
            "message": "已发送钉钉通知，请输入管理员OTP验证码",
            "application_id": application.id  # 返回申请ID以便后续跟踪
        })

    except Exception as e:
        logger.error(f"申请流程错误: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"申请失败: {str(e)}"}, status=500)

# 验证OTP令牌
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
        duration = float(data.get("duration", 0))  # 改为float以支持小数
        application_id = data.get("application_id")  # 获取申请ID

        logger.debug(f"收到OTP验证请求: user={user.user_name}, code={token_code}, server_id={server_id}")

        if not token_code or len(token_code) != 6 or not token_code.isdigit():
            return JsonResponse({"status": "error", "message": "验证码必须是6位数字"}, status=400)

        # 查找权限申请记录
        application = None
        if application_id:
            try:
                application = PermissionApplication.objects.get(id=application_id)
            except PermissionApplication.DoesNotExist:
                pass

        # 查找管理员令牌
        admin_user = UserInfo.objects.filter(otp_secret__isnull=False, otp_active=True).first()
        if not admin_user:
            # 更新申请状态为验证失败
            if application:
                application.status = 'verification_failed'
                application.verification_attempts += 1
                application.last_verification_attempt = timezone.now()
                application.save()
            return JsonResponse({"status": "error", "message": "未找到已激活的管理员令牌"}, status=400)

        # 验证OTP，使用配置文件中定义的窗口期
        totp = pyotp.TOTP(admin_user.otp_secret)
        if not totp.verify(token_code, valid_window=Config.OTP_VALID_WINDOW):
            # 更新申请状态为验证失败
            if application:
                application.status = 'verification_failed'
                application.verification_attempts += 1
                application.last_verification_attempt = timezone.now()
                application.save()
            return JsonResponse({"status": "error", "message": "令牌验证失败"}, status=401)

        # 验证成功，查找服务器
        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            # 更新申请状态为验证失败
            if application:
                application.status = 'verification_failed'
                application.verification_attempts += 1
                application.last_verification_attempt = timezone.now()
                application.save()
            return JsonResponse({"status": "error", "message": "服务器不存在"}, status=404)

        # 校验账号是否匹配
        if server.username != account_name:
            # 更新申请状态为验证失败
            if application:
                application.status = 'verification_failed'
                application.verification_attempts += 1
                application.last_verification_attempt = timezone.now()
                application.save()
            return JsonResponse({"status": "error", "message": "账号不匹配，请联系管理员"}, status=400)

        # 处理并发/生成密码
        result = handle_concurrent_requests(server_id, duration, account_name, user.user_name)
        if result is None:
            # 更新申请状态为验证失败
            if application:
                application.status = 'verification_failed'
                application.verification_attempts += 1
                application.last_verification_attempt = timezone.now()
                application.save()
            return JsonResponse({"status": "error", "message": "密码处理失败"}, status=500)

        password, is_shared, original_duration, expiration_time = result

        # 更新申请状态为已批准
        if application:
            application.status = 'approved'
            application.approved_at = timezone.now()
            application.verification_attempts += 1
            application.last_verification_attempt = timezone.now()
            application.save()

        # 返回给前端
        response_data = {
            "status": "success",
            "server_info": {
                "host": server.host,
                "port": server.port,
                "username": account_name,
                "password": password,
                "expiration": expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                "applicant": user.user_name,
                "application_time": timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        if is_shared:
            response_data["message"] = f"您正在使用共享密码，有效期为 {original_duration} 小时"

        logger.info(f"OTP验证成功，返回服务器信息: user={user.user_name}, server={server.host}")
        return JsonResponse(response_data)

    except Exception as e:
        logger.error(f"OTP验证失败: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"验证失败: {str(e)}"}, status=500)

def handle_concurrent_requests(server_id, duration, account_name, applicant_name):
    """
    处理并发请求，生成密码并设置过期时间
    
    参数:
        server_id: 服务器ID
        duration: 时长（小时，支持小数）
        account_name: 账户名
        applicant_name: 申请人姓名
    
    返回:
        (密码, 是否共享, 原始时长, 过期时间) 或 None
    """
    try:
        logger.info(f"处理并发请求: server_id={server_id}, duration={duration}小时, account={account_name}")
        
        with transaction.atomic():
            # 锁定服务器记录以防止并发问题
            server = ServerInfo.objects.select_for_update().get(id=server_id)
            
            now = timezone.now()
            # 计算过期时间（支持小数小时）
            expiration_time = now + timedelta(hours=duration)
            
            # 检查是否已有未过期的密码
            if server.password_expiration_time and server.password_expiration_time > now:
                # 如果有未过期的密码，检查是否是批量申请的统一密码
                if server.generated_password:
                    # 这是批量申请的统一密码，允许共享
                    logger.info(f"服务器 {server.host} 的密码在并发期间已被处理")
                    return (server.generated_password, True, server.current_duration, server.password_expiration_time)
                else:
                    # 这是单独申请的密码，不允许共享
                    logger.info(f"服务器 {server.host} 已有未过期的独立密码")
                    return (server.get_password(), True, server.current_duration, server.password_expiration_time)
            
            # 生成新密码
            new_password = generate_random_password()
            
            # 更新服务器密码
            if update_server_password(server, new_password, account_name):
                # 更新服务器记录
                server.password_expiration_time = expiration_time
                server.current_duration = duration
                server.last_password_change = now
                server.generated_password = None  # 独立密码不设置generated_password
                server.set_password(new_password)  # 更新加密的密码字段
                server.save()
                
                logger.info(f"服务器 {server.host} 密码处理成功")
                return (new_password, False, duration, expiration_time)
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
    """
    检查并更新已过期的密码
    这个函数可以由定时任务定期调用
    """
    from django.utils import timezone
    from django.db import transaction
    import logging
    
    logger = logging.getLogger(__name__)
    """检查服务器密码过期的后台任务"""
    try:
        logger = logging.getLogger(__name__)
        logger.info("开始检查服务器密码过期情况")
        now = timezone.now()
        expired_servers = ServerInfo.objects.filter(
            password_expiration_time__lte=now
        ).exclude(
            password_expiration_time__isnull=True
        )
        
        updated_count = 0
        for server in expired_servers:
            try:
                # 为每个过期的服务器生成独立的随机密码
                new_password = generate_random_password()
                
                # 更新服务器密码
                if update_server_password(server, new_password, server.username):
                    # 清除过期时间和其他相关字段
                    server.password_expiration_time = None
                    server.current_duration = 0
                    server.generated_password = None
                    server.last_password_change = now
                    server.set_password(new_password)  # 更新加密的密码字段
                    server.save()
                    
                    updated_count += 1
                    logger.info(f"服务器 {server.host} 的密码已过期并更新成功")
                else:
                    logger.error(f"服务器 {server.host} 密码更新失败")
                    
            except Exception as e:
                logger.error(f"更新服务器 {server.host} 密码时出错: {str(e)}", exc_info=True)
        
        logger.info(f"过期密码检查完成，共更新 {updated_count} 个服务器")
        return updated_count
        
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"检查过期密码时出错: {str(e)}", exc_info=True)
        return 0

# 生成随机密码
def generate_random_password(length=16):
    """生成安全的随机密码，排除影响识别的特殊字符"""
    exclude_chars = '$^`"\'\\|'  # 排除可能影响识别的特殊字符
    allowed_punctuation = ''.join(c for c in string.punctuation if c not in exclude_chars)
    alphabet = string.ascii_letters + string.digits + allowed_punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))



# 更新服务器密码
def update_server_password(server, new_password, account_name):
    """
    通过SSH连接服务器更新密码

    参数:
        server: ServerInfo对象
        new_password: 新密码（明文）
        account_name: 要更新密码的账户名

    返回:
        bool: 更新是否成功
    """
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 连接服务器
        logger.info(f"尝试连接服务器 {server.host}:{server.port} 使用用户 {server.username}")
        ssh.connect(
            hostname=server.host,
            port=server.port,
            username=server.username,
            password=server.get_password(),  # 使用解密后的密码
            timeout=getattr(settings, 'SSH_CONNECT_TIMEOUT', 10),
            look_for_keys=False  # 禁用密钥查找，只使用密码认证
        )
        logger.info(f"成功连接到服务器 {server.host}")

        # 转义密码中的特殊字符，避免shell解释
        escaped_password = new_password.replace("'", "'\"'\"'")
        escaped_account = account_name.replace("'", "'\"'\"'")
        escaped_sudo_password = server.get_password().replace("'", "'\"'\"'")
        
        # 使用sudo chpasswd命令更新密码（处理明文密码）
        # 使用-S选项从标准输入读取sudo密码，避免交互式密码提示
        command = f"printf '%s:%s\\n' '{account_name}' '{new_password}' | sudo /usr/sbin/chpasswd 2>&1"
        logger.info(f"执行命令: {command}")
        
        stdin, stdout, stderr = ssh.exec_command(
            command,
            timeout=getattr(settings, 'SSH_EXEC_TIMEOUT', 30)
        )

        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')
        
        logger.info(f"命令执行输出: {output}")
        logger.info(f"命令执行错误输出: {error_output}")
        logger.info(f"命令退出状态: {exit_status}")
        
        ssh.close()

        # 检查执行结果
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
    
# 用户资料视图
@login_required
def profile(request):
    """用户资料视图"""
    user = request.user
    logger.info(f"用户 {user.user_name} 访问个人资料")

    context = {
        'username': user.user_name,
        'phone': user.phone,
        'join_date': user.date_joined.strftime('%Y-%m-%d'),
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else '从未登录'
    }

    return render(request, 'profile.html', context)


# 刷新令牌API
def refresh_token(request):
    """刷新JWT令牌的API视图"""
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': '用户未认证'
        }, status=401)

    try:
        # 获取用户
        user = request.user

        # 生成新的访问令牌
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # 创建响应对象
        response = JsonResponse({
            'status': 'success',
            'message': '令牌刷新成功'
        })

        # 设置新的HTTP-only cookie，使用秒数而不是timedelta对象
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            max_age=int(timedelta(hours=3).total_seconds()),  # 3小时有效期
            samesite='Lax',
            secure=settings.SECURE_COOKIE
        )

        logger.info(f"用户 {user.user_name} 刷新令牌成功")
        return response

    except Exception as e:
        logger.error(f"令牌刷新失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': '令牌刷新失败'
        }, status=500)


# 检查令牌有效性
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


# 修改密码视图
@login_required
def change_password(request):
    """修改密码视图"""
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        user = request.user

        # 验证旧密码
        if not user.check_password(old_password):
            return JsonResponse({
                'status': 'error',
                'message': '旧密码不正确'
            })

        # 验证新密码是否一致
        if new_password != confirm_password:
            return JsonResponse({
                'status': 'error',
                'message': '两次输入的新密码不一致'
            })

        # 验证新密码复杂性
        if len(new_password) < 8:
            return JsonResponse({
                'status': 'error',
                'message': '密码长度至少为8个字符'
            })
        elif not re.search(r'[A-Z]', new_password):  # 检查大写字母
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个大写字母'
            })
        elif not re.search(r'[a-z]', new_password):  # 检查小写字母
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个小写字母'
            })
        elif not re.search(r'[0-9]', new_password):  # 检查数字
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个数字'
            })
        elif not re.search(r'[^A-Za-z0-9]', new_password):  # 检查特殊字符
            return JsonResponse({
                'status': 'error',
                'message': '密码必须包含至少一个特殊字符'
            })

        # 设置新密码
        user.set_password(new_password)
        user.save()

        #重新登录用户时指定认证后端
        auth_login(request, user, backend='app01.views.CustomModelBackend')

        return JsonResponse({
            'status': 'success',
            'message': '密码修改成功'
        })


    # GET请求显示修改密码页面
    return render(request, 'change_password.html')

@login_required
@require_GET
def system_token_management(request):
    """系统唯一令牌管理接口"""
    # 查询系统中是否已有密钥
    admin_with_token = UserInfo.objects.filter(otp_secret__isnull=False).first()
    current_user = request.user

    # 检查是否是管理员
    if not current_user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足，仅管理员可管理令牌'
        }, status=403)

    if not admin_with_token:
        # 没有密钥，为当前用户生成
        secret = pyotp.random_base32()
        current_user.otp_secret = secret
        current_user.otp_active = False  # 不自动激活，等待用户验证
        current_user.save()
        # 生成二维码，设置窗口期为2
        totp = pyotp.totp.TOTP(secret, interval=30, digits=6, digest=hashlib.sha1)
        otp_uri = totp.provisioning_uri(
            name=current_user.user_name,
            issuer_name="权限管理系统"
        )
        img = qrcode.make(otp_uri)
        buffer = BytesIO()
        img.save(buffer, 'PNG')
        img_str = b64encode(buffer.getvalue()).decode()
        return JsonResponse({
            'status': 'success',
            'otp_secret': secret,
            'qr_code': img_str,
            'message': '已为您生成系统密钥，请扫码绑定并验证'
        })
    elif admin_with_token.id == current_user.id:
        # 密钥属于当前用户，直接展示二维码
        secret = current_user.otp_secret
        # 如果当前用户没有密钥，则生成一个
        if not secret:
            secret = pyotp.random_base32()
            current_user.otp_secret = secret
            current_user.otp_active = False  # 不自动激活，等待用户验证
            current_user.save()
            
        totp = pyotp.totp.TOTP(secret, interval=30, digits=6, digest=hashlib.sha1)
        otp_uri = totp.provisioning_uri(
            name=current_user.user_name,
            issuer_name="权限管理系统"
        )
        img = qrcode.make(otp_uri)
        buffer = BytesIO()
        img.save(buffer, 'PNG')
        img_str = b64encode(buffer.getvalue()).decode()
        return JsonResponse({
            'status': 'success',
            'otp_secret': secret,
            'qr_code': img_str,
            'message': '请使用认证器扫描二维码并输入验证码完成绑定'
        })
    else:
        # 密钥属于其他用户，不允许重复生成
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
def decrypt_server_password(request, server_id):
    """解密服务器密码（需要OTP验证）"""
    if not request.user.is_superuser:
        logger.warning(f"非管理员用户 {request.user.user_name} 尝试解密服务器密码")
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)
    
    try:
        # 获取请求数据
        data = json.loads(request.body)
        token_code = data.get('token_code', '').strip()
        
        # 验证OTP令牌
        if not token_code:
            logger.warning(f"用户 {request.user.user_name} 尝试解密密码时未提供OTP验证码")
            return JsonResponse({
                'status': 'error',
                'message': '验证码不能为空'
            }, status=400)
        
        if len(token_code) != 6 or not token_code.isdigit():
            logger.warning(f"用户 {request.user.user_name} 提供了无效的OTP验证码: {token_code}")
            return JsonResponse({
                'status': 'error',
                'message': '验证码必须是6位数字'
            }, status=400)
        
        # 查找系统中激活的管理员令牌
        admin_user = UserInfo.objects.filter(otp_secret__isnull=False, otp_active=True).first()
        if not admin_user:
            logger.warning(f"系统中未找到激活的管理员令牌，用户 {request.user.user_name} 尝试解密密码")
            return JsonResponse({
                'status': 'error',
                'message': '系统中未找到激活的管理员令牌'
            }, status=400)
        
        # 验证OTP，使用配置文件中定义的窗口期
        totp = pyotp.TOTP(admin_user.otp_secret)
        if not totp.verify(token_code, valid_window=Config.OTP_VALID_WINDOW):
            logger.warning(f"用户 {request.user.user_name} OTP验证失败")
            return JsonResponse({
                'status': 'error',
                'message': '令牌验证失败，请重试'
            }, status=401)
        
        # 查找服务器
        try:
            server = ServerInfo.objects.get(id=server_id)
        except ServerInfo.DoesNotExist:
            logger.warning(f"用户 {request.user.user_name} 尝试解密不存在的服务器ID: {server_id}")
            return JsonResponse({
                'status': 'error',
                'message': '服务器不存在'
            }, status=404)
        
        # 解密并返回密码
        try:
            decrypted_password = server.get_password()
            # 确保密码是字符串类型，而不是字节类型
            if isinstance(decrypted_password, bytes):
                decrypted_password = decrypted_password.decode('utf-8')
            logger.info(f"管理员 {request.user.user_name} 成功解密了服务器 {server.host} 的密码")
        except Exception as e:
            logger.error(f"解密服务器 {server.host} 密码失败: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': '密码解密失败'
            }, status=500)
        
        return JsonResponse({
            'status': 'success',
            'password': decrypted_password
        })
        
    except json.JSONDecodeError:
        logger.error(f"用户 {request.user.user_name} 提供了无效的JSON数据")
        return JsonResponse({
            'status': 'error',
            'message': '请求数据格式错误'
        }, status=400)
    except Exception as e:
        logger.error(f"解密服务器密码失败: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': '解密失败'
        }, status=500)
    

@login_required
@require_http_methods(["GET"])
def check_server_account_exists(request):
    """检查服务器和账户名组合是否存在"""
    try:
        # 获取查询参数
        host = request.GET.get('host')
        username = request.GET.get('username')
        
        if not host or not username:
            return JsonResponse({
                'status': 'error',
                'message': '缺少主机地址或用户名参数'
            }, status=400)
        
        # 查找服务器信息
        exists = ServerInfo.objects.filter(host=host, username=username).exists()
        
        return JsonResponse({
            'status': 'success',
            'exists': exists
        })
        
    except Exception as e:
        logger.error(f"检查服务器账户组合失败: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': '检查失败'
        }, status=500)


# 查询服务器账户密码过期时间
@require_http_methods(["GET"])
def check_server_password_expiration(request):
    """查询服务器账户密码过期时间"""
    try:
        # 获取查询参数
        host = request.GET.get('host')
        username = request.GET.get('username')
        
        if not host or not username:
            return JsonResponse({
                'status': 'error',
                'message': '缺少主机地址或用户名参数'
            }, status=400)
        
        # 查找服务器信息
        try:
            server = ServerInfo.objects.get(host=host, username=username)
        except ServerInfo.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': '未找到指定的服务器信息'
            }, status=404)
        
        # 检查是否有过期时间
        if not server.password_expiration_time:
            return JsonResponse({
                'status': 'success',
                'data': {
                    'has_expiration': False,
                    'message': '当前服务器账户没有设置密码过期时间'
                }
            })
        
        # 检查是否已过期
        now = timezone.now()
        if server.password_expiration_time <= now:
            return JsonResponse({
                'status': 'success',
                'data': {
                    'has_expiration': False,
                    'message': '密码已过期'
                }
            })
        
        # 查找最近的权限申请记录，获取申请者信息
        try:
            latest_application = PermissionApplication.objects.filter(
                server=server,
                account_name=username,
                status='approved'
            ).latest('approved_at')
            
            applicant_name = latest_application.applicant.user_name
            application_time = latest_application.approved_at.strftime('%Y-%m-%d %H:%M:%S')
        except PermissionApplication.DoesNotExist:
            applicant_name = '未知'
            application_time = '未知'
        
        # 返回过期时间信息
        return JsonResponse({
            'status': 'success',
            'data': {
                'has_expiration': True,
                'host': server.host,
                'port': server.port,
                'username': server.username,
                'expiration': server.password_expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                'applicant': applicant_name,
                'application_time': application_time
            }
        })
        
    except Exception as e:
        logger.error(f"查询服务器密码过期时间失败: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': '查询失败'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def bulk_delete_users(request):
    """批量删除用户（仅限管理员）"""
    if not request.user.is_superuser:
        return JsonResponse({
            'status': 'error',
            'message': '权限不足'
        }, status=403)

    try:
        data = json.loads(request.body)
        user_ids = data.get('user_ids', [])
        
        if not user_ids or not isinstance(user_ids, list):
            return JsonResponse({
                'status': 'error',
                'message': '未提供有效的用户ID列表'
            }, status=400)
        
        # 检查是否尝试删除管理员用户或自己
        users_to_delete = UserInfo.objects.filter(id__in=user_ids)
        for user in users_to_delete:
            if user.is_superuser:
                return JsonResponse({
                    'status': 'error',
                    'message': '不能删除管理员用户'
                }, status=403)
            if user.id == request.user.id:
                return JsonResponse({
                    'status': 'error',
                    'message': '不能删除当前登录的用户'
                }, status=400)
        
        # 批量删除用户
        deleted_count, _ = users_to_delete.delete()
        
        return JsonResponse({
            'status': 'success',
            'message': f'成功删除 {deleted_count} 个用户'
        })
    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': '请求数据格式错误'
        }, status=400)
    except Exception as e:
        logger.error(f"批量删除用户失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': f'批量删除失败: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def verify_current_user_token(request):
    """验证当前用户的OTP令牌（用于激活自己的令牌）"""
    user = request.user

    try:
        # 检查用户是否是管理员
        if not user.is_superuser:
            return JsonResponse({
                'status': 'error',
                'message': '权限不足'
            }, status=403)

        # 检查用户是否有OTP密钥
        if not user.otp_secret:
            return JsonResponse({
                'status': 'error',
                'message': '用户没有OTP密钥'
            }, status=400)

        # 获取请求数据
        data = json.loads(request.body)
        token_code = data.get('token_code', '').strip()

        # 验证OTP令牌
        if not token_code:
            return JsonResponse({
                'status': 'error',
                'message': '验证码不能为空'
            }, status=400)

        if len(token_code) != 6 or not token_code.isdigit():
            return JsonResponse({
                'status': 'error',
                'message': '验证码必须是6位数字'
            }, status=400)

        # 验证OTP，使用配置文件中定义的窗口期
        totp = pyotp.TOTP(user.otp_secret, interval=30, digits=6, digest=hashlib.sha1)
        if totp.verify(token_code, valid_window=Config.OTP_VALID_WINDOW):
            # 验证成功，标记OTP已激活
            user.otp_active = True
            user.save()
            return JsonResponse({
                'status': 'success',
                'message': '令牌验证成功，已激活！'
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': '令牌验证失败，请重试'
            })

    except json.JSONDecodeError:
        logger.error(f"用户 {user.user_name} 提供了无效的JSON数据")
        return JsonResponse({
            'status': 'error',
            'message': '请求数据格式错误'
        }, status=400)
    except Exception as e:
        logger.error(f"验证当前用户令牌失败: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': f'验证失败: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["GET"])
def available_servers_for_user(request):
    """
    获取用户可申请的服务器列表（供普通用户查看）
    只返回主机地址和账户名，不返回密码等敏感信息
    """
    try:
        # 获取所有服务器信息（不包含密码等敏感信息）
        servers = ServerInfo.objects.all().values(
            'id',
            'host',
            'port',
            'username',
            'description'
        )
        
        # 转换为列表并返回
        servers_list = list(servers)
        
        return JsonResponse({
            'status': 'success',
            'data': servers_list
        })
    except Exception as e:
        logger.error(f"获取可申请服务器列表失败: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': '获取服务器列表失败'
        }, status=500)

@login_required
def server_list(request):
    """显示所有可申请的服务器列表页面"""
    return render(request, 'server_list.html')

@login_required
def bulk_apply(request):
    """批量权限申请页面"""
    user = request.user
    logger.info(f"用户 {user.user_name} 访问批量申请页面")

    # 获取服务器数据，用于自动完成
    servers = list(ServerInfo.objects.all().values('id', 'host', 'port', 'username', 'description'))
    
    # 获取时长选项
    duration_options = Config.get_duration_options()
    
    context = {
        'servers': json.dumps(servers),
        'duration_options': duration_options
    }
    
    return render(request, 'bulk_apply.html', context)


@login_required
@require_http_methods(["POST"])
def bulk_apply_permission(request):
    """批量权限申请处理"""
    import json
    user = request.user

    try:
        data = json.loads(request.body)
        applications = data.get("applications", [])
        reason = data.get("reason", "").strip()
        duration = float(data.get("duration", 0))  # 改为float以支持小数

        logger.debug(f"Bulk apply data - applications: {applications}, reason: '{reason}', duration: {duration}")
        logger.debug(f"Applications count: {len(applications)}")

        if not applications:
            return JsonResponse({"status": "error", "message": "未提供申请信息"}, status=400)
        
        if not reason:
            return JsonResponse({"status": "error", "message": "请填写申请原因"}, status=400)

        # 生成统一的临时密码
        unified_password = generate_random_password()
        
        # 存储申请结果
        application_results = []
        
        # 处理每个申请，只创建申请记录，不更新服务器密码
        for i, app in enumerate(applications):
            server_id = int(app.get("server_id"))
            account_name = app.get("account_name", "").strip()
            host = app.get("host", "").strip()

            logger.debug(f"Processing app {i} - server_id: {server_id}, account_name: '{account_name}', host: '{host}'")

            if not account_name or duration <= 0:
                logger.error(f"Invalid data for app {i} - account_name: '{account_name}', duration: {duration}")
                return JsonResponse({"status": "error", "message": "账户名或时长无效"}, status=400)

            # 找到服务器
            try:
                server = ServerInfo.objects.get(id=server_id)
                logger.debug(f"Found server for app {i}: {server}")
            except ServerInfo.DoesNotExist:
                logger.error(f"Server not found for app {i}: id={server_id}")
                return JsonResponse({"status": "error", "message": f"服务器 {host} 不存在"}, status=404)

            # 验证账户名是否与服务器关联
            logger.debug(f"Validating account for app {i}: server.username='{server.username}', account_name='{account_name}'")
            if server.username != account_name:
                logger.error(f"Account mismatch for app {i}: server.username='{server.username}', account_name='{account_name}'")
                return JsonResponse({"status": "error", "message": f"账户名 {account_name} 与服务器 {host} 配置不匹配"}, status=400)

            # 创建申请记录
            application = PermissionApplication.objects.create(
                applicant=user,
                server=server,
                account_name=account_name,
                reason=reason,
                duration=duration,
                status='verification_pending'  # 等待验证
            )

            # 添加到结果列表
            application_results.append({
                'application_id': application.id,
                'server_id': server.id,
                'host': server.host,
                'port': server.port,
                'username': account_name,  # 这就是account_name
                'account_name': account_name,  # 添加account_name字段确保兼容性
                'applicant': user.user_name,
                'duration': duration
            })

        # 查找已激活的管理员令牌用于生成OTP验证码
        admin_user = UserInfo.objects.filter(is_superuser=True, otp_secret__isnull=False, otp_active=True).first()
        otp_code = None
        if admin_user:
            totp = pyotp.TOTP(admin_user.otp_secret, interval=30, digits=6, digest='sha1', 
                              name=admin_user.user_name, issuer='权限管理系统')
            otp_code = totp.now()
            
            # 更新申请记录，标记验证码已发送
            for app_result in application_results:
                try:
                    application = PermissionApplication.objects.get(id=app_result['application_id'])
                    application.verification_code_sent = True
                    application.verification_code_sent_at = timezone.now()
                    application.save()
                except PermissionApplication.DoesNotExist:
                    pass

        # 发送钉钉通知
        title = "批量权限申请通知"
        
        # 构建服务器信息列表
        server_info_list = [f"{app['username']}@{app['host']}:{app['port']}" for app in application_results]
        server_info_text = "\n".join(server_info_list)
        
        content = (
            f"## 批量权限申请通知\n\n"
            f"- **申请人**: {user.user_name}\n"
            f"- **申请数量**: {len(applications)}\n"
            f"- **申请时长**: {duration}小时\n"
            f"- **申请原因**: {reason}\n"
            f"- **申请时间**: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- **申请服务器列表**:\n{server_info_text}\n"
            f"- **管理员OTP验证码**: {otp_code}\n"
        
        )
        send_dingtalk_message(title, content)

        logger.info(f"用户 {user.user_name} 的批量申请已提交，等待管理员验证，共处理 {len(applications)} 个申请")

        return JsonResponse({
            "status": "notify_sent",
            "message": "已发送钉钉通知，请输入管理员OTP验证码",
            "applications": application_results,
            "password": unified_password
        })

    except Exception as e:
        logger.error(f"批量申请流程错误: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"申请失败: {str(e)}"}, status=500)
    

@login_required
@require_http_methods(["POST"])
def verify_bulk_otp(request):
    """验证批量申请的OTP令牌并更新服务器密码"""
    import json
    user = request.user

    try:
        data = json.loads(request.body)
        token_code = data.get("token_code", "")
        applications = data.get("applications", [])
        unified_password = data.get("password", "")

        logger.debug(f"收到批量申请OTP验证请求: user={user.user_name}, code={token_code}")
        logger.debug(f"Applications data: {applications}")
        logger.debug(f"Applications count: {len(applications)}")

        if not token_code or len(token_code) != 6 or not token_code.isdigit():
            return JsonResponse({"status": "error", "message": "验证码必须是6位数字"}, status=400)

        # 查找管理员令牌
        admin_user = UserInfo.objects.filter(otp_secret__isnull=False, otp_active=True).first()
        if not admin_user:
            return JsonResponse({"status": "error", "message": "未找到已激活的管理员令牌"}, status=400)

        # 验证OTP，使用配置文件中定义的窗口期
        totp = pyotp.TOTP(admin_user.otp_secret)
        if not totp.verify(token_code, valid_window=Config.OTP_VALID_WINDOW):
            return JsonResponse({"status": "error", "message": "令牌验证失败"}, status=401)

        # 存储申请结果
        application_results = []
        
        # 处理每个申请
        for i, app in enumerate(applications):
            application_id = app.get("application_id")
            server_id = app.get("server_id")
            account_name = app.get("account_name", "").strip()
            host = app.get("host", "").strip()
            duration = float(app.get("duration") or 0)
            applicant_name = app.get("applicant", "").strip()
            
            logger.debug(f"Processing application {i}: application_id={application_id}, server_id={server_id}, account_name='{account_name}', host='{host}'")

            # 找到服务器
            try:
                server = ServerInfo.objects.get(id=server_id)
                logger.debug(f"Found server for app {i}: {server}")
            except ServerInfo.DoesNotExist:
                logger.error(f"服务器不存在 for app {i}: id={server_id}")
                return JsonResponse({"status": "error", "message": f"服务器 {host} 不存在"}, status=404)
            except Exception as e:
                logger.error(f"查找服务器时出错 for app {i}: {str(e)}")
                return JsonResponse({"status": "error", "message": f"查找服务器时出错: {str(e)}"}, status=500)

            # 验证账户名是否与服务器关联
            logger.debug(f"Validating account for app {i}: server.username='{server.username}', account_name='{account_name}'")
            if server.username != account_name:
                logger.error(f"账户名不匹配 for app {i}: server.username='{server.username}', account_name='{account_name}'")
                return JsonResponse({"status": "error", "message": f"账户名 {account_name} 与服务器 {host} 配置不匹配"}, status=400)

            # 更新服务器密码
            if update_server_password(server, unified_password, account_name):
                # 设置密码过期时间
                expiration_time = timezone.now() + timedelta(hours=duration)
                
                # 更新服务器记录
                server.password_expiration_time = expiration_time
                server.current_duration = duration
                server.last_password_change = timezone.now()
                server.generated_password = unified_password  # 保存生成的密码
                server.set_password(unified_password)  # 更新加密的密码字段
                server.save()
                
                # 更新申请记录状态
                try:
                    application = PermissionApplication.objects.get(id=application_id)
                    application.status = 'approved'
                    application.approved_at = timezone.now()
                    application.save()
                except PermissionApplication.DoesNotExist:
                    logger.warning(f"申请记录不存在: id={application_id}")
                    pass  # 如果找不到申请记录，继续处理其他记录
                
                # 添加到结果列表
                application_results.append({
                    'host': server.host,
                    'port': server.port,
                    'username': account_name,
                    'applicant': applicant_name,
                    'expiration': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'password': unified_password
                })
                
                logger.info(f"用户 {user.user_name} 的批量申请成功更新服务器 {server.host} 的密码")
            else:
                logger.error(f"用户 {user.user_name} 的批量申请更新服务器 {server.host} 密码失败")
                return JsonResponse({"status": "error", "message": f"更新服务器 {server.host} 密码失败"}, status=500)

        logger.info(f"管理员 {user.user_name} 验证OTP成功，批量申请处理完成")

        return JsonResponse({
            "status": "success",
            "message": "批量申请成功",
            "passwords": application_results
        })

    except Exception as e:
        logger.error(f"批量申请OTP验证失败: {str(e)}", exc_info=True)
        return JsonResponse({"status": "error", "message": f"验证失败: {str(e)}"}, status=500)
    
    """检查服务器密码过期的后台任务"""
    try:
        logger.info("开始检查服务器密码过期情况")
        now = timezone.now()
        expired_servers = ServerInfo.objects.filter(
            password_expiration_time__lte=now
        ).exclude(
            password_expiration_time__isnull=True
        )
        
        updated_count = 0
        for server in expired_servers:
            try:
                # 为每个过期的服务器生成独立的随机密码
                new_password = generate_random_password()
                
                # 更新服务器密码
                if update_server_password(server, new_password, server.username):
                    # 清除过期时间和其他相关字段
                    server.password_expiration_time = None
                    server.current_duration = 0
                    server.generated_password = None
                    server.last_password_change = now
                    server.set_password(new_password)  # 更新加密的密码字段
                    server.save()
                    
                    updated_count += 1
                    logger.info(f"服务器 {server.host} 的密码已过期并更新成功")
                else:
                    logger.error(f"服务器 {server.host} 密码更新失败")
                    
            except Exception as e:
                logger.error(f"更新服务器 {server.host} 密码时出错: {str(e)}", exc_info=True)
        
        logger.info(f"过期密码检查完成，共更新 {updated_count} 个服务器")
        return updated_count
        
    except Exception as e:
        logger.error(f"检查过期密码时出错: {str(e)}", exc_info=True)
        return 0