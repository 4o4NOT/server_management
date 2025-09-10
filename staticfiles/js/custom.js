document.addEventListener('DOMContentLoaded', function () {
    // 自动完成
    const targetHostInput = document.getElementById('targetHost');
    const hostSuggestions = document.getElementById('hostSuggestions');
    let serverData = [];

    // 倒计时相关变量
    let countdownInterval = null;
    let expirationTime = null;

    // 安全地解析服务器数据
    try {
        serverData = JSON.parse('{{ servers_json|escapejs }}');
    } catch (e) {
        console.error('服务器数据解析失败:', e);
        serverData = [];
    }

    // 页面加载时检查是否有未过期的权限
    checkExistingPermissions();

    targetHostInput.addEventListener('input', function () {
        const query = this.value.toLowerCase().trim();
        if (query.length < 1) {
            hostSuggestions.classList.add('hidden');
            return;
        }
        const matchedServers = serverData.filter(server =>
            server.host.toLowerCase().includes(query) ||
            (server.description && server.description.toLowerCase().includes(query))
        ).slice(0, 5);

        if (matchedServers.length > 0) {
            const fragment = document.createDocumentFragment();
            matchedServers.forEach(server => {
                const div = document.createElement('div');
                div.className = 'p-2 hover:bg-light cursor-pointer';
                div.textContent = `${server.host}${server.description ? ' - ' + server.description : ''}`;
                div.dataset.id = server.id;
                div.dataset.host = server.host;
                fragment.appendChild(div);
            });
            hostSuggestions.innerHTML = '';
            hostSuggestions.appendChild(fragment);
            hostSuggestions.classList.remove('hidden');
        } else {
            hostSuggestions.innerHTML = '<div class="p-2 text-muted">没有找到匹配的服务器</div>';
            hostSuggestions.classList.remove('hidden');
        }
    });

    // 使用事件委托处理点击事件
    hostSuggestions.addEventListener('mousedown', function (e) {
        const item = e.target.closest('[data-id]');
        if (item) {
            targetHostInput.value = item.dataset.host;
            hostSuggestions.classList.add('hidden');
        }
    });

    targetHostInput.addEventListener('blur', function () {
        setTimeout(() => hostSuggestions.classList.add('hidden'), 200);
    });

    // TOTP模态框初始化
    const totpModal = new bootstrap.Modal(document.getElementById('totpModal'));
    let applyData = null;

    // 权限申请表单提交，只弹出令牌验证框
    document.getElementById('applyForm').addEventListener('submit', function (e) {
        // 阻止表单默认提交行为
        e.preventDefault();
        console.log("表单提交事件触发");

        const accountName = document.getElementById('accountName').value.trim();
        const targetHost = document.getElementById('targetHost').value.trim();
        const duration = document.getElementById('duration').value;

        if (!accountName || !targetHost || !duration) {
            alert('请填写所有必填字段');
            return;
        }

        const matchedServer = serverData.find(server => server.host === targetHost);
        if (!matchedServer) {
            alert('缺少该服务器配置，请联系管理员添加主机和用户信息');
            return;
        }

        // 保存申请数据
        applyData = {
            server_id: matchedServer.id,
            account_name: accountName,
            duration: duration
        };

        // 显示令牌验证模态框
        console.log("显示模态框");
        totpModal.show();
        return false; // 进一步确保不提交表单
    });

    // 令牌验证通过后提交申请
    document.getElementById('verifyTotpBtn').addEventListener('click', async () => {
        const totpCode = document.getElementById('totpCode').value.trim();
        if (!totpCode || totpCode.length !== 6 || !/^\d+$/.test(totpCode)) {
            alert('请输入有效的6位数字验证码');
            return;
        }

        const verifyBtn = document.getElementById('verifyTotpBtn');
        const originalText = verifyBtn.innerHTML;
        verifyBtn.innerHTML = '<span class="loading"></span> 验证中...';
        verifyBtn.disabled = true;

        try {
            const response = await fetch('{% url "verify_otp" %}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({
                    token_code: totpCode
                })
            });

            // 添加更详细的错误处理
            if (!response.ok) {
                let errorMessage = `HTTP错误: ${response.status}`;
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.message || errorMessage;
                } catch (e) {
                    // 如果无法解析错误响应，使用默认消息
                }
                throw new Error(errorMessage);
            }

            const result = await response.json();

            if (result.status === 'success') {
                totpModal.hide();
                document.getElementById('totpCode').value = '';
                submitPermissionApply(applyData);
            } else {
                alert(`验证失败: ${result.message || '未知错误'}`);
            }
        } catch (error) {
            console.error('验证请求失败:', error);
            alert(`验证请求失败: ${error.message || '请稍后再试'}`);
        } finally {
            verifyBtn.innerHTML = originalText;
            verifyBtn.disabled = false;
        }
    });

    // 权限申请提交
    async function submitPermissionApply(data) {
        const submitBtn = document.getElementById('submitBtn');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="loading"></span> 提交中...';
        submitBtn.disabled = true;

        try {
            const response = await fetch('{% url "apply_permission" %}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                throw new Error(`HTTP错误: ${response.status}`);
            }

            const result = await response.json();

            if (result.status === 'success') {
                const serverInfo = result.server_info;

                // 显示倒计时区域
                showCountdown(serverInfo);

                // 使用更安全的方式显示敏感信息
                const message = `申请成功！\n服务器: ${serverInfo.host}\n用户名: ${serverInfo.username}\n有效期至: ${serverInfo.expiration}`;
                if (confirm(message + '\n\n点击确定复制密码到剪贴板')) {
                    navigator.clipboard.writeText(serverInfo.password).then(() => {
                        alert('密码已复制到剪贴板');
                    }).catch(err => {
                        console.error('复制失败:', err);
                        alert(`密码: ${serverInfo.password}`);
                    });
                }
            } else {
                // 根据错误类型提供更具体的提示
                let errorMessage = result.message || '未知错误';
                if (errorMessage.includes('连接到服务器')) {
                    errorMessage += '\n\n请检查服务器配置或联系系统管理员。';
                } else if (errorMessage.includes('密码更新失败')) {
                    errorMessage += '\n\n请稍后重试或联系系统管理员。';
                }
                alert(`申请失败: ${errorMessage}`);
            }
        } catch (error) {
            console.error('申请请求失败:', error);
            alert('申请请求失败，请稍后再试');
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    // 检查现有权限
    async function checkExistingPermissions() {
        // 获取当前表单中的主机和账户信息
        const targetHost = document.getElementById('targetHost').value.trim();
        const accountName = document.getElementById('accountName').value.trim();
        
        // 如果表单中有主机和账户信息，则检查其过期时间
        if (targetHost && accountName) {
            try {
                const response = await fetch(`/check_server_password_expiration/?host=${encodeURIComponent(targetHost)}&username=${encodeURIComponent(accountName)}`);
                
                if (!response.ok) {
                    console.error('检查权限请求失败:', response.status);
                    return;
                }
                
                const result = await response.json();
                
                if (result.status === 'success' && result.data.has_expiration) {
                    // 显示倒计时
                    showCountdown(result.data);
                }
            } catch (error) {
                console.error('检查现有权限失败:', error);
            }
        }
    }

    // 显示倒计时
    function showCountdown(serverInfo) {
        // 设置过期时间
        expirationTime = new Date(serverInfo.expiration).getTime();
        const now = new Date().getTime();

        // 检查过期时间是否合理
        if (expirationTime <= now) {
            alert('警告：密码已过期或即将过期，请重新申请权限！');
            return;
        }

        // 填充服务器信息
       document.getElementById('serverInfo').textContent = `${serverInfo.host}:${serverInfo.port}`;
    document.getElementById('accountInfo').textContent = `${serverInfo.username}`;

        // 显示倒计时区域
        const countdownSection = document.getElementById('countdownSection');
        countdownSection.style.display = 'block';

        // 添加入场动画
        countdownSection.classList.remove('fade-in');
        void countdownSection.offsetWidth; // 触发重排
        countdownSection.classList.add('fade-in');

        // 开始倒计时
        startCountdown();

        // 平滑滚动到倒计时区域
        setTimeout(() => {
            countdownSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
    }

    // 开始倒计时
    function startCountdown() {
        // 清除之前的倒计时（如果有的话）
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }

        // 开始新的倒计时
        countdownInterval = setInterval(updateCountdown, 1000);

        // 立即更新一次
        updateCountdown();
    }

    // 更新倒计时显示
    function updateCountdown() {
        const now = new Date().getTime();
        const distance = expirationTime - now;

        // 获取数字元素
        const daysElement = document.getElementById('days');
        const hoursElement = document.getElementById('hours');
        const minutesElement = document.getElementById('minutes');
        const secondsElement = document.getElementById('seconds');

        // 如果已经过期
        if (distance < 0) {
            clearInterval(countdownInterval);
            daysElement.textContent = '00';
            hoursElement.textContent = '00';
            minutesElement.textContent = '00';
            secondsElement.textContent = '00';
            daysElement.classList.add('countdown-critical');
            hoursElement.classList.add('countdown-critical');
            minutesElement.classList.add('countdown-critical');
            secondsElement.classList.add('countdown-critical');
            return;
        }

        // 计算天、小时、分钟和秒
        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        // 更新显示
        daysElement.textContent = days.toString().padStart(2, '0');
        hoursElement.textContent = hours.toString().padStart(2, '0');
        minutesElement.textContent = minutes.toString().padStart(2, '0');
        secondsElement.textContent = seconds.toString().padStart(2, '0');

        // 根据剩余时间应用不同的样式
        // 移除之前的样式
        daysElement.classList.remove('countdown-critical');
        hoursElement.classList.remove('countdown-critical');
        minutesElement.classList.remove('countdown-critical');
        secondsElement.classList.remove('countdown-critical');

        // 如果剩余时间少于10分钟，添加紧急警告样式
        if (days === 0 && hours === 0 && minutes < 10) {
            daysElement.classList.add('countdown-critical');
            hoursElement.classList.add('countdown-critical');
            minutesElement.classList.add('countdown-critical');
            secondsElement.classList.add('countdown-critical');
            
            // 添加脉冲动画
            document.querySelector('.countdown-display-container').classList.add('countdown-warning');
        } 
        // 如果剩余时间少于1小时，添加警告样式
        else if (days === 0 && hours === 0 && minutes < 60) {
            document.querySelector('.countdown-display-container').classList.add('countdown-warning');
        } 
        // 否则移除警告样式
        else {
            document.querySelector('.countdown-display-container').classList.remove('countdown-warning');
        }
    }

    // 获取CSRF token的辅助函数
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // 页面卸载时清除倒计时
    window.addEventListener('beforeunload', function () {
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
    });
});