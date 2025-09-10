document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    const errorAlert = document.getElementById('errorAlert');
    const errorMessage = document.getElementById('errorMessage');
    const loginBtn = document.getElementById('loginBtn');
    const passwordInput = document.getElementById('password');
    const togglePassword = document.getElementById('togglePassword');

    // 密码显示/隐藏切换
    togglePassword.addEventListener('click', function () {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
    });

    // 登录表单提交
    loginForm.addEventListener('submit', function (e) {
        e.preventDefault();

        // 重置错误状态
        errorAlert.style.display = 'none';

        // 获取表单元素
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;

        // 显示加载状态
        submitBtn.innerHTML = '<span class="loading"></span> 登录中...';
        submitBtn.disabled = true;

        // 收集表单数据
        const formData = new FormData(loginForm);

        // 发送登录请求
        fetch(loginForm.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // 登录成功，重定向到首页
                    window.location.href = data.redirect_url || '/index/';
                } else if (data.message === '账户已被禁用，请联系管理员') {
                    // 特殊样式提示
                    errorMessage.textContent = data.message;
                    errorAlert.style.display = 'block';
                    errorAlert.classList.add('alert-danger');

                    // 添加额外引导
                    const contactMsg = document.createElement('p');
                    contactMsg.innerHTML = '<i class="fas fa-envelope me-2"></i> 联系管理员: wzj@servyou.com.cn';
                    errorAlert.appendChild(contactMsg);

                    // 恢复按钮状态
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                } else {
                    // 登录失败，显示错误信息
                    errorMessage.textContent = data.message || '登录失败，请重试';
                    errorAlert.style.display = 'block';
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('登录请求失败:', error);
                errorMessage.textContent = '登录请求失败，请稍后再试';
                errorAlert.style.display = 'block';
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
    });
});