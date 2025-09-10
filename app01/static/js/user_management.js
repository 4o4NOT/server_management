document.addEventListener('DOMContentLoaded', function () {
    let currentUserId = null;
    let currentUserName = null;
    let pendingAction = null;
    let qrCodeInstance = null;
    let currentTokenSecret = null; // 保存当前令牌密钥

    // 全选/取消全选功能
    $('#selectAllCheckbox').on('change', function() {
        const isChecked = $(this).prop('checked');
        $('.user-checkbox').prop('checked', isChecked);
        updateBulkDeleteButtonState();
    });

    // 单个复选框状态改变时更新全选状态和批量删除按钮
    $(document).on('change', '.user-checkbox', function() {
        updateSelectAllCheckboxState();
        updateBulkDeleteButtonState();
    });

    // 更新全选复选框状态
    function updateSelectAllCheckboxState() {
        const allChecked = $('.user-checkbox').length > 0 && $('.user-checkbox:checked').length === $('.user-checkbox').length;
        $('#selectAllCheckbox').prop('checked', allChecked);
    }

    // 更新批量删除按钮状态
    function updateBulkDeleteButtonState() {
        const selectedCount = $('.user-checkbox:checked').length;
        $('#bulkDeleteBtn').prop('disabled', selectedCount === 0);
    }

    // 批量删除按钮点击事件
    $('#bulkDeleteBtn').on('click', function() {
        const selectedUsers = $('.user-checkbox:checked');
        if (selectedUsers.length === 0) {
            alert('请至少选择一个用户');
            return;
        }

        // 检查是否选择了管理员用户
        let hasAdmin = false;
        selectedUsers.each(function() {
            const isAdmin = $(this).closest('tr').find('td:eq(6) i').hasClass('fa-check-circle');
            if (isAdmin) {
                hasAdmin = true;
                return false; // 跳出循环
            }
        });
        
        if (hasAdmin) {
            alert('不能删除管理员用户');
            return;
        }

        const userIds = [];
        const userNames = [];
        selectedUsers.each(function() {
            userIds.push($(this).data('user-id'));
            const userName = $(this).closest('tr').find('td:eq(1) span').text();
            userNames.push(userName);
        });

        if (confirm(`确定要删除以下 ${userNames.length} 个用户吗？此操作不可恢复。\n\n${userNames.join(', ')}`)) {
            // 发送批量删除请求
            $.ajax({
                url: '/bulk_delete_users/',
                type: 'POST',
                headers: {
                    'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val() || $('[name=csrfmiddlewaretoken]').val(),
                    'Content-Type': 'application/json'
                },
                data: JSON.stringify({
                    'user_ids': userIds
                }),
                success: function(response) {
                    if (response.status === 'success') {
                        // 从表格中移除已删除的用户行
                        userIds.forEach(function(userId) {
                            $(`tr[data-user-id="${userId}"]`).fadeOut(300, function() {
                                $(this).remove();
                            });
                        });
                        // 取消全选
                        $('#selectAllCheckbox').prop('checked', false);
                        updateBulkDeleteButtonState();
                        showSuccessToast(response.message);
                    } else {
                        alert('批量删除失败: ' + response.message);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('批量删除用户失败:', error);
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        alert('批量删除失败: ' + xhr.responseJSON.message);
                    } else {
                        alert('批量删除用户失败，请稍后重试');
                    }
                }
            });
        }
    });

    // 添加重置密码按钮事件监听器
    $(document).on('click', '.reset-pwd-btn', function() {
        const userId = $(this).data('user-id');
        const userName = $(this).data('user-name');
        currentUserId = userId;
        currentUserName = userName;
        // 设置模态框中的用户信息
        $('#resetPasswordModal .modal-title').text('重置密码 - ' + userName);
        $('#resetPasswordModal').modal('show');
    });

    // 添加删除用户按钮事件监听器
    $(document).on('click', '.delete-user-btn', function() {
        const userId = $(this).data('user-id');
        const userName = $(this).data('user-name');
        
        // 检查目标用户是否为管理员
        const isAdmin = $(this).closest('tr').find('td:eq(6) i').hasClass('fa-check-circle');
        if (isAdmin) {
            alert('不能删除管理员用户');
            return;
        }
        
        if (confirm(`确定要删除用户 "${userName}" 吗？此操作不可恢复。`)) {
            // 发送删除请求
            $.ajax({
                url: `/delete_user/${userId}/`,
                type: 'POST',
                headers: {
                    'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val() || $('[name=csrfmiddlewaretoken]').val()
                },
                success: function(response) {
                    if (response.status === 'success') {
                        // 从表格中移除该用户行
                        $(`tr[data-user-id="${userId}"]`).fadeOut(300, function() {
                            $(this).remove();
                            updateSelectAllCheckboxState();
                        });
                        showSuccessToast('用户删除成功');
                    } else {
                        alert('删除失败: ' + response.message);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('删除用户失败:', error);
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        alert('删除失败: ' + xhr.responseJSON.message);
                    } else {
                        alert('删除用户失败，请稍后重试');
                    }
                }
            });
        }
    });

    // 添加启用/禁用按钮事件监听器
    $(document).on('click', '.toggle-status-btn', function() {
        const userId = $(this).data('user-id');
        const status = $(this).data('user-status'); // 1=启用, 0=禁用
        const button = $(this);
        const userName = $(this).closest('tr').find('td:eq(1) span').text();
        
        // 检查目标用户是否为管理员
        const isAdmin = $(this).closest('tr').find('td:eq(6) i').hasClass('fa-check-circle');
        if (isAdmin) {
            alert('不能操作管理员账户');
            return;
        }
        
        const action = status == 1 ? '启用' : '禁用';
        
        if (confirm(`确定要${action}用户 "${userName}" 吗？`)) {
            // 发送状态更新请求
            $.ajax({
                url: `/toggle_user_active/${userId}/`,
                type: 'POST',
                headers: {
                    'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val() || $('[name=csrfmiddlewaretoken]').val()
                },
                data: {
                    'is_active': status
                },
                success: function(response) {
                    if (response.status === 'success') {
                        // 更新按钮状态和文本
                        if (status == 1) {
                            // 从启用改为禁用
                            button.removeClass('btn-success').addClass('btn-danger')
                                  .html('<i class="fas fa-ban me-1"></i>禁用')
                                  .data('user-status', 0);
                        } else {
                            // 从禁用改为启用
                            button.removeClass('btn-danger').addClass('btn-success')
                                  .html('<i class="fas fa-check me-1"></i>启用')
                                  .data('user-status', 1);
                        }
                        showSuccessToast('用户状态更新成功');
                    } else {
                        alert('状态更新失败: ' + response.message);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('更新用户状态失败:', error);
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        alert('更新用户状态失败: ' + xhr.responseJSON.message);
                    } else {
                        alert('更新用户状态失败，请稍后重试');
                    }
                }
            });
        }
    });

    // 重置密码表单提交
    $('#resetPasswordForm').on('submit', function(e) {
        e.preventDefault();
        
        const newPassword = $('#newPassword').val();
        const confirmPassword = $('#confirmPassword').val();
        
        if (newPassword !== confirmPassword) {
            alert('两次输入的密码不一致');
            return;
        }
        
        if (!currentUserId) {
            alert('未选择用户');
            return;
        }
        
        // 检查目标用户是否为管理员
        const targetRow = $(`.user-checkbox[data-user-id="${currentUserId}"]`).closest('tr');
        const isAdmin = targetRow.find('td:eq(6) i').hasClass('fa-check-circle');
        if (isAdmin) {
            alert('不能重置管理员的密码');
            return;
        }
        
        // 发送重置密码请求
        $.ajax({
            url: `/reset_password/${currentUserId}/`,
            type: 'POST',
            headers: {
                'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val() || $('[name=csrfmiddlewaretoken]').val()
            },
            data: {
                'new_password': newPassword,
                'confirm_new_password': confirmPassword
            },
            success: function(response) {
                if (response.status === 'success') {
                    showSuccessToast('密码重置成功');
                    $('#resetPasswordModal').modal('hide');
                    // 清空表单
                    $('#resetPasswordForm')[0].reset();
                } else {
                    alert('重置失败: ' + response.message);
                }
            },
            error: function(xhr, status, error) {
                console.error('重置密码失败:', error);
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    alert('重置失败: ' + xhr.responseJSON.message);
                } else {
                    alert('重置密码失败，请稍后重试');
                }
            }
        });
    });

    // 令牌管理按钮点击事件（当前用户）
    $('#currentUserTokenBtn').on('click', function () {
        $('#tokenInfo').html('<p>正在加载令牌信息...</p>');
        $('#tokenQrCode').hide();
        $('#tokenVerify').hide();
        $('#resetTokenBtn').hide();
        $('#verifyTokenBtn').hide();
        $('#qrCodeContainer').html('');
        $('#manageTokenModal').modal('show');

        // 调用后端接口
        $.ajax({
            url: '/system_token_management/',
            type: 'GET',
            success: function (data) {
                if (data.status === 'success') {
                    // 保存令牌密钥
                    currentTokenSecret = data.otp_secret;

                    // 展示二维码和密钥
                    $('#tokenInfo').html(`<p>${data.message}</p>`);
                    $('#qrCodeContainer').html(
                        `<img src="data:image/png;base64,${data.qr_code}" style="width:200px;height:200px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);" />`
                    );
                    $('#tokenSecret').text(`密钥: ${data.otp_secret}`);
                    $('#tokenQrCode').show();
                    $('#tokenVerify').show();
                    $('#verifyTokenBtn').show();
                    $('#resetTokenBtn').show();
                } else {
                    // 展示错误提示
                    $('#tokenInfo').html(`<p class="text-danger">${data.message}</p>`);
                    $('#qrCodeContainer').html('');
                    $('#tokenQrCode').hide();
                    $('#tokenVerify').hide();
                    $('#verifyTokenBtn').hide();
                    $('#resetTokenBtn').hide();
                }
            },
            error: function (xhr, status, error) {
                console.error('获取令牌信息失败:', error);
                $('#tokenInfo').html('<p class="text-danger">获取令牌信息失败</p>');
                $('#qrCodeContainer').html('');
                $('#tokenQrCode').hide();
                $('#tokenVerify').hide();
                $('#verifyTokenBtn').hide();
                $('#resetTokenBtn').hide();
            }
        });
    });

    // 验证令牌按钮点击事件
    $('#verifyTokenBtn').on('click', function () {
        const tokenCode = $('#tokenCode').val().trim();

        if (!tokenCode || tokenCode.length !== 6 || !/^\d+$/.test(tokenCode)) {
            alert('请输入有效的6位数字验证码');
            return;
        }

        // 禁用按钮并显示加载状态
        const verifyBtn = $(this);
        const originalText = verifyBtn.html();
        verifyBtn.html('<span class="loading"></span> 验证中...');
        verifyBtn.prop('disabled', true);

        // 发送验证请求到新的端点，用于验证当前用户自己的令牌
        $.ajax({
            url: '/api/verify_current_user_token/',
            type: 'POST',
            headers: {
                'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val() || $('[name=csrfmiddlewaretoken]').val() || '{{ csrf_token }}',
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                token_code: tokenCode
            }),
            success: function (data) {
                if (data.status === 'success') {
                    showSuccessToast(data.message);
                    // 隐藏验证部分，显示成功信息
                    $('#tokenVerify').hide();
                    $('#verifyTokenBtn').hide();
                    $('#tokenInfo').html('<p class="text-success">' + data.message + '</p>');
                    // 更新重置按钮文本
                    $('#resetTokenBtn').html('<i class="fas fa-redo me-1"></i>重新生成令牌');
                } else {
                    alert(`验证失败: ${data.message}`);
                }
            },
            error: function (xhr, status, error) {
                console.error('验证失败:', error);
                let errorMessage = '验证失败，请稍后重试';
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    errorMessage = xhr.responseJSON.message;
                }
                alert(errorMessage);
            },
            complete: function () {
                // 恢复按钮状态
                verifyBtn.html(originalText);
                verifyBtn.prop('disabled', false);
            }
        });
    });

    // 重置令牌按钮点击事件
    $('#resetTokenBtn').on('click', function () {
        showConfirmDialog('重置令牌', `确定要重置系统令牌吗？重置后需要重新绑定。`);
        pendingAction = {
            type: 'reset-token'
        };
    });

    // 确认操作（包括重置令牌）
    $('#confirmActionBtn').on('click', function () {
        if (!pendingAction) return;

        if (pendingAction.type === 'reset-token') {
            // 发送重置令牌请求
            $.ajax({
                url: '/system_token_management/',
                type: 'GET',
                success: function (response) {
                    if (response.status === 'success') {
                        showSuccessToast('系统令牌已重置');
                        // 更新显示新令牌信息
                        currentTokenSecret = response.otp_secret;
                        $('#tokenInfo').html(`<p>${response.message}</p>`);
                        $('#qrCodeContainer').html(
                            `<img src="data:image/png;base64,${response.qr_code}" style="width:200px;height:200px;border-radius:8px;box-shadow:0 4px 8px rgba(0,0,0,0.1);" />`
                        );
                        $('#tokenSecret').text(`密钥: ${response.otp_secret}`);
                        $('#tokenCode').val(''); // 清空验证码输入框
                    } else {
                        alert(response.message);
                    }
                },
                error: function (xhr, status, error) {
                    console.error('重置令牌失败:', error);
                    alert('重置令牌失败');
                }
            });
        }
        // 关闭确认对话框
        $('#confirmDialog').hide();
        pendingAction = null;
    });

    // 显示二维码函数
    function displayTokenQrCode(secret, userName) {
        // 构建TOTP URI
        const totpUri = `otpauth://totp/权限申请系统:${userName}?secret=${secret}&issuer=权限申请系统`;

        // 清除之前的二维码
        if (qrCodeInstance) {
            qrCodeInstance.clear();
        }

        // 生成新的二维码
        $('#qrCodeContainer').html('<canvas id="qrCodeCanvas"></canvas>');
        const canvas = document.getElementById('qrCodeCanvas');
        qrCodeInstance = new QRCode(canvas, {
            text: totpUri,
            width: 200,
            height: 200,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });

        // 显示密钥
        $('#tokenSecret').text(`密钥: ${secret}`);
        $('#qrCodeContainer').show();
        $('#tokenQrCode').show();
    }

    // 显示确认对话框函数
    function showConfirmDialog(title, message) {
        $('#confirmDialogTitle').text(title);
        $('#confirmDialogMessage').html(message);
        $('#confirmDialog').show();
    }

    // 显示成功提示
    function showSuccessToast(message) {
        // 移除已存在的toast
        $('.success-toast').remove();

        // 创建新的toast
        const toast = $(`
                <div class="success-toast">
                    <i class="fas fa-check-circle"></i>
                    <span>${message}</span>
                </div>
            `);

        $('body').append(toast);

        // 3秒后自动消失
        setTimeout(() => {
            toast.fadeOut(300, function () {
                $(this).remove();
            });
        }, 3000);
    }
});