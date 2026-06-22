"""
服务器权限管理系统 — 视图包

将所有子模块的视图函数重新导出，保持 url.py 的兼容性：
    from app01 import views
    views.user_login, views.index, views.verify_otp, ...
"""

# 认证模块
from app01.views.auth import (
    CustomModelBackend,
    user_login,
    user_logout,
    register,
    profile,
    change_password,
    refresh_token,
    check_token,
)

# 用户管理模块
from app01.views.user_mgmt import (
    user_management,
    delete_user,
    toggle_user_active,
    reset_password,
    bulk_delete_users,
)

# 服务器管理模块
from app01.views.server import (
    server_management,
    add_server,
    update_server,
    delete_server,
    decrypt_server_password,
    test_ssh_connection,
    update_server_password,
)

# 权限申请模块
from app01.views.permission import (
    apply_permission,
    verify_otp,
    handle_concurrent_requests,
    check_expired_passwords,
    generate_random_password,
)

# 批量操作模块
from app01.views.batch import (
    bulk_apply_permission,
    verify_bulk_otp,
    get_batch_server_passwords,
)

# OTP 管理模块
from app01.views.otp import (
    otp_management,
    system_token_management,
    verify_token_page,
    verify_current_user_token,
    get_user_token,
    generate_token,
    verify_token,
    reset_token,
)

# 工具查询模块
from app01.views.utils import (
    available_servers_for_user,
    check_server_account_exists,
    check_server_password_expiration,
)

# 页面模块
from app01.views.pages import (
    index,
    server_list,
    bulk_apply,
    health_check,
)

# 公共工具函数（供其他模块导入）
from app01.views.common import (
    send_dingtalk_message,
    find_user_by_identifier,
    validate_password_complexity,
    verify_admin_otp,
    admin_required,
    jwt_login_required,
)
