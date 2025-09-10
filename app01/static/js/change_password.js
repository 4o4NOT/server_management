document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('changePasswordForm');
    const errorAlert = document.getElementById('errorAlert');
    const successAlert = document.getElementById('successAlert');
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');
    const submitBtn = document.getElementById('submitBtn');

    // 密码显示/隐藏切换
    function setupPasswordToggle(inputId, toggleId) {
        const passwordInput = document.getElementById(inputId);
        const toggleButton = document.getElementById(toggleId);

        if (passwordInput && toggleButton) {
            toggleButton.addEventListener('click', function () {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
            });
        }
    }

    // 设置密码切换功能
    setupPasswordToggle('old_password', 'toggleOldPassword');
    setupPasswordToggle('new_password', 'toggleNewPassword');
    setupPasswordToggle('confirm_password', 'toggleConfirmPassword');

    // 表单提交处理
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        // 重置错误状态
        errorAlert.style.display = 'none';
        successAlert.style.display = 'none';

        // 获取表单数据
        const oldPassword = document.getElementById('old_password').value.trim();
        const newPassword = document.getElementById('new_password').value.trim();
        const confirmPassword = document.getElementById('confirm_password').value.trim();

        // 简单前端验证
        let hasError = false;

        if (!oldPassword) {
            showError('请输入当前密码');
            hasError = true;
        }

        if (!newPassword) {
            showError('请输入新密码');
            hasError = true;
        } else if (!isPasswordValid(newPassword)) {
            showError('新密码不符合要求');
            hasError = true;
        }

        if (!confirmPassword) {
            showError('请确认新密码');
            hasError = true;
        } else if (newPassword !== confirmPassword) {
            showError('两次输入的新密码不一致');
            hasError = true;
        }

        if (hasError) return;

        // 显示加载状态
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="loading"></span> 修改中...';
        submitBtn.disabled = true;

        // 收集表单数据
        const formData = new FormData(form);

        // 发送修改密码请求
        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
            .then(response => {
                // 首先检查HTTP状态码
                if (!response.ok) {
                    throw new Error(`HTTP错误! 状态: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    // 修改成功
                    showSuccess(data.message);

                    // 3秒后重定向到首页
                    setTimeout(() => {
                        window.location.href = "/index/";
                    }, 2000);
                } else {
                    // 修改失败
                    showError(data.message || '密码修改失败');
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            })
            .catch(error => {
                // 精确错误分类
                if (error instanceof TypeError) {
                    showError('服务器响应格式错误');
                } else {
                    showError('密码修改请求失败，请稍后再试');
                }
                console.error('密码修改请求失败:', error);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
    });

    // 密码复杂性验证函数
    function isPasswordValid(password) {
        return password.length >= 8 &&
            /[A-Z]/.test(password) && // 包含大写字母
            /[a-z]/.test(password) && // 包含小写字母
            /[0-9]/.test(password) && // 包含数字
            /[^A-Za-z0-9]/.test(password); // 包含特殊字符
    }

    // 显示错误消息
    function showError(message) {
        errorMessage.textContent = message;
        errorAlert.style.display = 'block';
        errorAlert.classList.remove('alert-success');
        errorAlert.classList.add('alert-danger');
        errorAlert.style.background = 'var(--secondary-gradient)';
    }

    // 显示成功消息
    function showSuccess(message) {
        successMessage.textContent = message;
        successAlert.style.display = 'block';
        successAlert.classList.remove('alert-danger');
        successAlert.classList.add('alert-success');
        successAlert.style.background = 'var(--success-gradient)';
    }
});