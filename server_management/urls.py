# server_management/urls.py

from django.contrib import admin
from django.urls import path
from app01 import views
from django.views.generic import RedirectView
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
import os
from django.urls import path, re_path

urlpatterns = [
    # 首页和认证相关
    # path('', views.index, name='index'),
    path('index/', views.index, name='index'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('register/', views.register, name='register'),
    
    # 用户相关功能
    path('profile/', views.profile, name='profile'),
    path('change_password/', views.change_password, name='change_password'),
    # 用户可申请的服务器列表
    path('api/available_servers/', views.available_servers_for_user, name='available_servers'),
     # 可申请的服务器列表页面
    path('server_list/', views.server_list, name='server_list'),
    # 批量申请页面
    path('bulk_apply/', views.bulk_apply, name='bulk_apply'),
    
    # 管理员功能
    #path('management/', views.management, name='management'),
    path('otp-management/', views.otp_management, name='otp_management'),
    path('server_management/', views.server_management, name='server_management'),
    path('user_management/', views.user_management, name='user_management'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('toggle_user_active/<int:user_id>/', views.toggle_user_active, name='toggle_user_active'),
    path('reset_password/<int:user_id>/', views.reset_password, name='reset_password'),

    # API端点
    path('api/refresh-token/', views.refresh_token, name='refresh_token'),
    path('api/check-token/', views.check_token, name='check_token'),
    path('api/verify-otp/', views.verify_otp, name='verify_otp'),
    path('api/apply-permission/', views.apply_permission, name='apply_permission'),
    path('api/bulk-apply-permission/', views.bulk_apply_permission, name='bulk_apply_permission'),  # 添加批量申请API
    path('api/verify-bulk-otp/', views.verify_bulk_otp, name='verify_bulk_otp'),  # 添加批量申请OTP验证API
    path('api/add_server/', views.add_server, name='add_server'),
    path('api/update_server/<int:server_id>/', views.update_server, name='update_server'),
    path('api/delete_server/<int:server_id>/', views.delete_server, name='delete_server'),
    # 添加解密服务器密码的API端点
    path('api/decrypt_server_password/<int:server_id>/', views.decrypt_server_password, name='decrypt_server_password'),
    # 令牌管理API
    path('api/get_user_token/<int:user_id>/', views.get_user_token, name='get_user_token'),
    path('api/generate_token/<int:user_id>/', views.generate_token, name='generate_token'),
    path('api/verify_token/', views.verify_token, name='verify_token'),
    path('api/verify_current_user_token/', views.verify_current_user_token, name='verify_current_user_token'),
    path('check_server_password_expiration/', views.check_server_password_expiration, name='check_server_password_expiration'),
    path('check_server_account_exists/', views.check_server_account_exists, name='check_server_account_exists'),
    #path('api/reset_token/<int:user_id>/', views.reset_token, name='reset_token'),
    path('system_token_management/', views.system_token_management, name='sys_token'),
    path('verify_token_page/', views.verify_token_page, name='verify_token_page'),

    # 批量删除用户API
    path('bulk_delete_users/', views.bulk_delete_users, name='bulk_delete_users'),


    
    # 重定向到首页
    path('', RedirectView.as_view(url='index/')),
]

# 自定义错误处理页面
#handler404 = 'app01.views.page_not_found'
#handler500 = 'app01.views.server_error'

# 静态文件服务配置
if settings.DEBUG:
    # 服务STATIC_ROOT中的文件
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # 服务STATICFILES_DIRS中的文件
    for static_dir in getattr(settings, 'STATICFILES_DIRS', []):
        urlpatterns += static(settings.STATIC_URL, document_root=static_dir)
        
        # 特别处理webfonts目录
        webfonts_path = os.path.join(static_dir, 'webfonts')
        if os.path.exists(webfonts_path):
            urlpatterns += [
                re_path(r'^static/webfonts/(?P<path>.*)$', serve, {
                    'document_root': webfonts_path,
                }),
            ]