document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('registerForm');
    const errorAlert = document.getElementById('errorAlert');
    const errorMessage = document.getElementById('errorMessage');
    const submitBtn = document.getElementById('submitBtn');
    const passwordInput = document.getElementById('password');
    const togglePassword = document.getElementById('togglePassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');

    // 密码显示/隐藏切换
    togglePassword.addEventListener('click', function () {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
    });

    toggleConfirmPassword.addEventListener('click', function () {
        const type = confirmPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        confirmPasswordInput.setAttribute('type', type);
        this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
    });

    // 表单提交处理
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        // 重置错误状态
        errorAlert.style.display = 'none';
        document.getElementById('usernameError').style.display = 'none';
        document.getElementById('phoneError').style.display = 'none';
        document.getElementById('passwordError').style.display = 'none';
        document.getElementById('confirmPasswordError').style.display = 'none';

        // 获取表单数据
        const username = document.getElementById('username').value.trim();
        const phone = document.getElementById('phone').value.trim();
        const password = document.getElementById('password').value.trim();
        const confirmPassword = document.getElementById('confirmPassword').value.trim();

        // 验证用户名（2-4个汉字）
        if (!/^[\u4e00-\u9fa5]{2,4}$/.test(username)) {
            document.getElementById('usernameError').style.display = 'block';
            return;
        }

        // 验证手机号 (11位数字)
        if (!/^\d{11}$/.test(phone)) {
            document.getElementById('phoneError').style.display = 'block';
            return;
        }

        // 验证密码是否一致
        if (password !== confirmPassword) {
            document.getElementById('confirmPasswordError').style.display = 'block';
            return;
        }

        // 验证密码复杂性
        if (password.length < 8) {
            showError('密码长度至少为8个字符');
            return;
        } else if (!/[A-Z]/.test(password)) {
            showError('密码必须包含至少一个大写字母');
            return;
        } else if (!/[a-z]/.test(password)) {
            showError('密码必须包含至少一个小写字母');
            return;
        } else if (!/[0-9]/.test(password)) {
            showError('密码必须包含至少一个数字');
            return;
        } else if (!/[^A-Za-z0-9]/.test(password)) {
            showError('密码必须包含至少一个特殊字符');
            return;
        }

        // 显示加载状态
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="loading"></span> 注册中...';
        submitBtn.disabled = true;

        // 收集表单数据
        const formData = new FormData(form);

        // 发送注册请求
        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // 注册成功，跳转到登录页
                    window.location.href = "{% url 'login' %}?register_success=true";
                } else {
                    // 注册失败，显示错误信息
                    showError(data.message || '注册失败');
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('注册请求失败:', error);
                showError('注册请求失败，请稍后再试');
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
    });

    // 显示错误消息
    function showError(message) {
        errorMessage.textContent = message;
        errorAlert.style.display = 'block';
    }
});