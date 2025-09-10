// 使用事件委托处理密码切换点击事件
function handlePasswordToggle(event) {
    const toggleButton = event.target.closest('.toggle-password');
    if (toggleButton) {
        event.preventDefault();
        // 创建一个模拟事件对象，确保currentTarget正确设置
        const simulatedEvent = {
            currentTarget: toggleButton
        };
        togglePasswordVisibility(simulatedEvent);
    }
}

// 存储密码明文的映射
const passwordMap = new Map();

// 添加密码显示/隐藏功能
function togglePasswordVisibility(event) {
    const button = event.currentTarget;
    const index = button.getAttribute('data-index');
    const serverId = button.getAttribute('data-server-id');
    const isVisible = button.getAttribute('data-visible') === 'true';
    const passwordCell = button.closest('.password-cell');
    const passwordText = passwordCell.querySelector('.password-text');

    if (isVisible) {
        // 隐藏密码
        passwordText.textContent = '••••••••';
        button.setAttribute('data-visible', 'false');
        button.innerHTML = '<i class="fas fa-eye"></i>';
    } else {
        // 显示密码需要OTP验证
        showPasswordOTPModal(serverId, passwordText, button);
    }
}

// 显示密码查看OTP验证模态框
function showPasswordOTPModal(serverId, passwordTextElement, toggleButton) {
    // 创建模态框
    const modalHtml = `
        <div class="modal-overlay" id="passwordOTPModalOverlay" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 10000;">
            <div class="modal-content" style="background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); max-width: 500px; width: 90%;">
                <div class="modal-header" style="padding: 1rem; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center;">
                    <h5 class="modal-title"><i class="fas fa-shield-alt me-2"></i>管理员验证</h5>
                    <button type="button" class="btn-close" id="closeModalBtn" style="background: none; border: none; font-size: 1.5rem; cursor: pointer;">&times;</button>
                </div>
                <div class="modal-body" style="padding: 1rem;">
                    <div class="alert alert-warning" style="background-color: #fff3cd; border-color: #ffeaa7; color: #856404; padding: 0.75rem; border-radius: 0.375rem; margin-bottom: 1rem;">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        出于安全考虑，查看服务器密码需要进行二次验证。
                    </div>
                    <p>请输入管理员令牌验证码以查看密码：</p>
                    <div class="mb-3">
                        <input type="text" class="form-control" id="otpCodeInput" placeholder="6位数字验证码" maxlength="6" autocomplete="off" style="width: 100%; padding: 0.375rem 0.75rem; border: 1px solid #ced4da; border-radius: 0.375rem;">
                        <div class="form-text" style="font-size: 0.875em; color: #6c757d; margin-top: 0.25rem;">需要管理员OTP令牌验证才能查看服务器密码</div>
                    </div>
                </div>
                <div class="modal-footer" style="padding: 1rem; border-top: 1px solid #eee; display: flex; justify-content: flex-end; gap: 0.5rem;">
                    <button type="button" class="btn btn-secondary" id="cancelOTPBtn" style="background-color: #6c757d; border: none; color: white; padding: 0.375rem 0.75rem; border-radius: 0.375rem; cursor: pointer;">取消</button>
                    <button type="button" class="btn btn-primary" id="verifyOTPBtn" style="background-color: #0d6efd; border: none; color: white; padding: 0.375rem 0.75rem; border-radius: 0.375rem; cursor: pointer;">
                        <span id="verifyOTPText">验证并查看</span>
                    </button>
                </div>
            </div>
        </div>
    `;

    // 添加模态框到页面
    if (!document.getElementById('passwordOTPModalOverlay')) {
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }

    // 获取模态框元素
    const modalOverlay = document.getElementById('passwordOTPModalOverlay');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const cancelOTPBtn = document.getElementById('cancelOTPBtn');

    // 显示模态框
    modalOverlay.style.display = 'flex';

    // 关闭模态框的函数
    function closeModal() {
        if (modalOverlay && modalOverlay.parentNode) {
            modalOverlay.parentNode.removeChild(modalOverlay);
        }
    }

    // 绑定关闭事件
    closeModalBtn.addEventListener('click', closeModal);
    cancelOTPBtn.addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', function (e) {
        if (e.target === modalOverlay) {
            closeModal();
        }
    });

    // 绑定验证按钮事件
    document.getElementById('verifyOTPBtn').addEventListener('click', function () {
        const otpCode = document.getElementById('otpCodeInput').value.trim();

        if (!otpCode || otpCode.length !== 6 || !/^\d+$/.test(otpCode)) {
            alert('请输入有效的6位数字验证码');
            return;
        }

        // 显示加载状态
        const verifyBtn = document.getElementById('verifyOTPBtn');
        const originalText = verifyBtn.innerHTML;
        verifyBtn.innerHTML = '<span class="loading"></span> 验证中...';
        verifyBtn.disabled = true;

        // 发送验证请求
        fetch(`/api/decrypt_server_password/${serverId}/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            },
            body: JSON.stringify({
                token_code: otpCode
            }),
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        throw new Error('OTP验证失败');
                    } else if (response.status === 403) {
                        throw new Error('权限不足');
                    } else {
                        throw new Error('验证请求失败');
                    }
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    // 显示密码
                    passwordTextElement.textContent = data.password;
                    toggleButton.setAttribute('data-visible', 'true');
                    toggleButton.innerHTML = '<i class="fas fa-eye-slash"></i>';

                    // 关闭模态框
                    setTimeout(closeModal, 100); // 稍微延迟关闭，确保DOM操作完成

                    // 30秒后自动隐藏密码
                    setTimeout(() => {
                        if (toggleButton.getAttribute('data-visible') === 'true') {
                            passwordTextElement.textContent = '••••••••';
                            toggleButton.setAttribute('data-visible', 'false');
                            toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
                        }
                    }, 30000);
                } else {
                    alert(`验证失败: ${data.message}`);
                }
            })
            .catch(error => {
                console.error('验证请求失败:', error);
                alert(`验证失败: ${error.message}`);
            })
            .finally(() => {
                // 恢复按钮状态
                // 使用setTimeout确保元素仍然存在
                setTimeout(() => {
                    const verifyBtn = document.getElementById('verifyOTPBtn');
                    if (verifyBtn) {
                        verifyBtn.innerHTML = originalText;
                        verifyBtn.disabled = false;
                    }
                }, 0);
            });
    });
}

// 加载服务器列表
function loadServers() {
    // 显示加载状态
    const tableBody = document.getElementById('serversTableBody');
    tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">加载中...</span>
                    </div>
                    正在加载服务器列表...
                </td>
            </tr>
        `;

    document.getElementById('noServersMessage').classList.add('d-none');

    fetch('/server_management/', {
        headers: {
            'x-requested-with': 'XMLHttpRequest',
            'Accept': 'application/json'
        },
        credentials: 'include'  // 包含cookie
    })
        .then(response => {
            if (response.status === 403) {
                throw new Error('权限不足，仅管理员可访问');
            }
            if (!response.ok) {
                throw new Error('网络响应异常');
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                const servers = data.data;
                const tableBody = document.getElementById('serversTableBody');
                const noServersMessage = document.getElementById('noServersMessage');

                tableBody.innerHTML = '';

                if (servers.length === 0) {
                    noServersMessage.classList.remove('d-none');
                    return;
                }

                noServersMessage.classList.add('d-none');

                servers.forEach((server, index) => {
                    // 存储密码明文
                    passwordMap.set(`server-${index}`, server.password || '');

                    const row = document.createElement('tr');

                    // 创建操作列
                    const actionCell = document.createElement('td');
                    actionCell.className = 'action-buttons';
                    actionCell.innerHTML = `
                        <button class="btn btn-sm btn-warning edit-server me-1" data-id="${server.id}" title="编辑">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm btn-danger delete-server" data-id="${server.id}" title="删除">
                            <i class="fas fa-trash"></i>
                        </button>
                    `;

                    row.innerHTML = `
                    <td>${server.target_host}</td>
                    <td>${server.target_port}</td>
                    <td>${server.username}</td>
                    <td class="password-cell">
                        <span class="password-text">••••••••</span>
                        <button class="toggle-password" data-index="${index}" data-server-id="${server.id}" data-visible="false">
                            <i class="fas fa-eye"></i>
                        </button>
                    </td>
                    <td>${server.description || '-'}</td>
                `;

                    // 添加操作列
                    row.appendChild(actionCell);
                    tableBody.appendChild(row);
                });


                // 绑定操作按钮事件
                bindServerActions();
            } else {
                throw new Error(data.message || '获取服务器列表失败');
            }
        })
        .catch(error => {
            console.error('加载服务器列表失败:', error);
            document.getElementById('serversTableBody').innerHTML = '';
            const noServersMessage = document.getElementById('noServersMessage');
            noServersMessage.classList.remove('d-none');
            noServersMessage.innerHTML = `<i class="fas fa-ban me-1"></i>${error.message}`;
        });
}

// 绑定服务器操作事件
function bindServerActions() {
    // 绑定编辑按钮事件
    document.querySelectorAll('.edit-server').forEach(button => {
        button.addEventListener('click', editServer);
    });

    // 绑定删除按钮事件
    document.querySelectorAll('.delete-server').forEach(button => {
        button.addEventListener('click', deleteServer);
    });
}

// 编辑服务器
function editServer(event) {
    const serverId = event.currentTarget.getAttribute('data-id');
    const row = event.currentTarget.closest('tr');
    const cells = row.querySelectorAll('td');

    // 获取服务器信息
    const host = cells[0].textContent;
    const port = cells[1].textContent;
    const username = cells[2].textContent;
    const description = cells[4].textContent === '-' ? '' : cells[4].textContent;

    // 填充表单
    document.getElementById('host').value = host;
    document.getElementById('port').value = port;
    document.getElementById('username').value = username;
    document.getElementById('description').value = description;

    // 设置隐藏字段表示编辑模式
    const form = document.getElementById('serverForm');
    form.dataset.editMode = 'true';
    form.dataset.serverId = serverId;

    // 更改UI以显示编辑模式
    document.getElementById('formTitle').style.display = 'none';
    document.getElementById('editTitle').style.display = 'inline';
    document.getElementById('submitText').style.display = 'none';
    document.getElementById('updateText').style.display = 'inline';
    document.getElementById('editingIndicator').style.display = 'flex';
    document.getElementById('cancelEdit').style.display = 'block';
    document.getElementById('serverFormCard').classList.add('edit-mode');

    // 显示正在编辑的服务器信息
    const editingServerInfo = document.getElementById('editingServerInfo');
    editingServerInfo.textContent = `正在编辑: ${username}@${host}:${port}`;
    editingServerInfo.style.display = 'block';

    // 添加动画效果以吸引用户注意
    const formCard = document.getElementById('serverFormCard');
    formCard.classList.remove('highlight-edit');
    void formCard.offsetWidth; // 触发重排
    formCard.classList.add('highlight-edit');

    // 滚动到表单区域
    setTimeout(() => {
        formCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}
// 处理取消编辑的函数
function handleCancelEdit() {
    resetFormToAddMode();
}
// 取消编辑
const cancelEditButton = document.getElementById('cancelEdit');
if (cancelEditButton) {
    cancelEditButton.addEventListener('click', handleCancelEdit);
}

// 重置表单到添加模式
function resetFormToAddMode() {
    // 安全获取元素并操作
    const serverForm = document.getElementById('serverForm');
    if (serverForm) {
        serverForm.reset();
        serverForm.removeAttribute('data-edit-mode');
        serverForm.removeAttribute('data-server-id');
    }

    // 确保添加服务器标题显示
    const formTitle = document.getElementById('formTitle');
    if (formTitle) formTitle.style.display = 'inline';

    // 确保编辑服务器标题隐藏
    const editTitle = document.getElementById('editTitle');
    if (editTitle) editTitle.style.display = 'none';

    // 确保添加按钮文本显示
    const submitText = document.getElementById('submitText');
    if (submitText) submitText.style.display = 'inline';

    // 确保更新按钮文本隐藏
    const updateText = document.getElementById('updateText');
    if (updateText) updateText.style.display = 'none';

    // 确保编辑指示器隐藏
    const editingIndicator = document.getElementById('editingIndicator');
    if (editingIndicator) editingIndicator.style.display = 'none';

    // 确保取消编辑按钮隐藏
    const cancelEdit = document.getElementById('cancelEdit');
    if (cancelEdit) cancelEdit.style.display = 'none';

    // 移除编辑模式样式
    const serverFormCard = document.getElementById('serverFormCard');
    if (serverFormCard && serverFormCard.classList) {
        serverFormCard.classList.remove('edit-mode');
    }

    // 隐藏编辑服务器信息
    const editingServerInfo = document.getElementById('editingServerInfo');
    if (editingServerInfo) editingServerInfo.style.display = 'none';
    if (editingServerInfo) editingServerInfo.textContent = '';

    // 清除高亮效果
    if (serverFormCard) {
        serverFormCard.classList.remove('highlight-edit');
    }
}

// 删除服务器
function deleteServer(event) {
    const serverId = event.currentTarget.getAttribute('data-id');
    const button = event.currentTarget;

    if (confirm('确定要删除这个服务器吗？')) {
        // 显示加载状态
        const originalHTML = button.innerHTML;
        button.innerHTML = '<span class="loading"></span>';
        button.disabled = true;

        fetch(`/api/delete_server/${serverId}/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()  // 添加CSRF令牌
            },
            credentials: 'include'  // 包含cookie
        })
        .then(response => {
            // 检查响应是否成功
            if (!response.ok) {
                throw new Error(`HTTP错误! 状态: ${response.status}`);
            }
            // 尝试解析JSON，如果失败则返回默认错误对象
            return response.json().catch(() => {
                return {
                    status: 'error',
                    message: '服务器返回了无效的响应格式'
                };
            });
        })
        .then(data => {
            if (data.status === 'success') {
                alert('服务器删除成功');
                loadServers(); // 刷新列表
            } else {
                throw new Error(data.message || '删除失败');
            }
        })
        .catch(error => {
            console.error('删除服务器失败:', error);
            alert('删除失败: ' + error.message);
        })
        .finally(() => {
            // 恢复按钮状态
            button.innerHTML = originalHTML;
            button.disabled = false;
        });
    }
}



// 获取CSRF令牌
function getCSRFToken() {
    const csrfToken = document.cookie.match(/csrftoken=([^;]+)/);
    return csrfToken ? csrfToken[1] : '';
}


// 确保DOM加载完成后执行
document.addEventListener('DOMContentLoaded', function () {
    // 确保初始状态下表单处于添加模式
    const serverForm = document.getElementById('serverForm');
    if (serverForm) {
        serverForm.removeAttribute('data-edit-mode');
        serverForm.removeAttribute('data-server-id');
    }

    // 确保添加服务器标题显示
    const formTitle = document.getElementById('formTitle');
    if (formTitle) formTitle.style.display = 'inline';

    // 确保编辑服务器标题隐藏
    const editTitle = document.getElementById('editTitle');
    if (editTitle) editTitle.style.display = 'none';

    // 确保添加按钮文本显示
    const submitText = document.getElementById('submitText');
    if (submitText) submitText.style.display = 'inline';

    // 确保更新按钮文本隐藏
    const updateText = document.getElementById('updateText');
    if (updateText) updateText.style.display = 'none';

    // 确保编辑指示器隐藏
    const editingIndicator = document.getElementById('editingIndicator');
    if (editingIndicator) editingIndicator.style.display = 'none';

    // 绑定取消编辑按钮事件
    const cancelEdit = document.getElementById('cancelEdit');
    if (cancelEdit) {
        // 移除可能已存在的事件监听器（防止重复绑定）
        cancelEdit.removeEventListener('click', handleCancelEdit);
        // 添加事件监听器
        cancelEdit.addEventListener('click', handleCancelEdit);
        cancelEdit.style.display = 'none';
    }

    // 移除编辑模式样式
    const serverFormCard = document.getElementById('serverFormCard');
    if (serverFormCard && serverFormCard.classList) {
        serverFormCard.classList.remove('edit-mode');
    }

    // 隐藏编辑服务器信息
    const editingServerInfo = document.getElementById('editingServerInfo');
    if (editingServerInfo) editingServerInfo.style.display = 'none';
    if (editingServerInfo) editingServerInfo.textContent = '';

    // 清除高亮效果
    if (serverFormCard) {
        serverFormCard.classList.remove('highlight-edit');
    }

    // 添加事件委托来处理密码切换
    document.addEventListener('click', handlePasswordToggle);
    loadServers();
    
    // 绑定表单提交事件（只绑定一次）
    if (serverForm) {
        serverForm.removeEventListener('submit', handleFormSubmit);
        serverForm.addEventListener('submit', handleFormSubmit);
    }
});


// 处理表单提交的函数
function handleFormSubmit(e) {
    e.preventDefault();
    console.log("表单提交事件触发");

    const submitBtn = document.getElementById('submitBtn');
    const isEditMode = this.dataset.editMode === 'true';
    const serverId = this.dataset.serverId;

    // 验证表单
    let isValid = true;
    const host = document.getElementById('host').value.trim();
    const port = document.getElementById('port').value;
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const description = document.getElementById('description').value.trim();

    console.log("表单数据:", {host, port, username, password, description});

    // 清除之前的错误消息
    document.querySelectorAll('.error-message').forEach(el => el.textContent = '');

    // 验证主机地址
    if (!host) {
        const hostError = document.getElementById('hostError');
        if (hostError) hostError.textContent = '请输入主机地址';
        isValid = false;
    }

    // 验证端口
    if (!port || port < 1 || port > 65535) {
        const portError = document.getElementById('portError');
        if (portError) portError.textContent = '端口号必须在1-65535之间';
        isValid = false;
    }

    // 验证用户名
    if (!username) {
        const usernameError = document.getElementById('usernameError');
        if (usernameError) usernameError.textContent = '请输入用户名';
        isValid = false;
    }

    // 验证密码
    if (!password) {
        const passwordError = document.getElementById('passwordError');
        if (passwordError) passwordError.textContent = '请输入密码';
        isValid = false;
    }

    if (!isValid) {
        console.log("表单验证失败");
        return;
    }

    // 显示加载状态
    const originalHTML = submitBtn ? submitBtn.innerHTML : '<span>提交</span>';
    if (submitBtn) {
        submitBtn.innerHTML = '<span class="loading"></span> 处理中...';
        submitBtn.disabled = true;
    }

    const formData = {
        host: host,
        port: parseInt(port) || 22,
        username: username,
        password: password,
        description: description
    };

    console.log("准备发送请求:", {isEditMode, serverId, formData});

    // 根据编辑模式选择URL和方法
    const url = isEditMode
        ? `/api/update_server/${serverId}/`
        : '/api/add_server/';

    const method = isEditMode ? 'POST' : 'POST';

    console.log("请求URL和方法:", {url, method});
    
    // 尝试将formData转换为JSON字符串
    let jsonData;
    try {
        jsonData = JSON.stringify(formData);
        console.log("JSON数据:", jsonData);
    } catch (error) {
        console.error("JSON序列化失败:", error);
        alert("数据格式化失败，请重试");
        if (submitBtn) {
            submitBtn.innerHTML = originalHTML;
            submitBtn.disabled = false;
        }
        return;
    }

    fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()  // 添加CSRF令牌
        },
        body: jsonData,
        credentials: 'include'  // 包含cookie
    })
    .then(response => {
        console.log("收到响应:", response.status, response.statusText);
        return response.json();
    })
    .then(data => {
        console.log("响应数据:", data);
        if (data.status === 'success') {
            // 显示成功消息
            alert(isEditMode ? '服务器更新成功!' : '服务器添加成功!');
            
            // 重置表单
            document.getElementById('serverForm').reset();
            
            // 重新加载服务器列表
            loadServers(); 

            // 重置编辑模式
            if (isEditMode) {
                resetFormToAddMode();
            }
        } else {
            throw new Error(data.message || (isEditMode ? '更新失败' : '添加失败'));
        }
    })
    .catch(error => {
        console.error(isEditMode ? '更新服务器失败:' : '添加服务器失败:', error);
        alert((isEditMode ? '更新服务器失败: ' : '添加服务器失败: ') + error.message);
    })
    .finally(() => {
        // 确保按钮状态被重置
        if (submitBtn) {
            submitBtn.innerHTML = isEditMode ? 
                '<span id="updateText"><i class="fas fa-save"></i>更新服务器</span>' : 
                '<span id="submitText"><i class="fas fa-plus"></i>添加服务器</span>';
            submitBtn.disabled = false;
        }
    });
}