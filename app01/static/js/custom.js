// 确保 navigator.clipboard 存在，如果不存在则创建一个模拟对象
(function() {
    if (typeof navigator !== 'undefined' && !navigator.clipboard) {
        navigator.clipboard = {
            writeText: function(text) {
                return new Promise(function(resolve, reject) {
                    try {
                        const textArea = document.createElement("textarea");
                        textArea.value = text;
                        textArea.style.top = "0";
                        textArea.style.left = "0";
                        textArea.style.position = "fixed";
                        textArea.style.opacity = "0";
                        document.body.appendChild(textArea);
                        textArea.focus();
                        textArea.select();
                        
                        const successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        
                        if (successful) {
                            resolve();
                        } else {
                            reject(new Error('无法复制文本'));
                        }
                    } catch (err) {
                        reject(err);
                    }
                });
            }
        };
    }
})();

document.addEventListener('DOMContentLoaded', function () {
    // 自动完成
    const targetHostInput = document.getElementById('targetHost');
    const hostSuggestions = document.getElementById('hostSuggestions');
    const accountNameSelect = document.getElementById('accountName');
    let serverData = [];

    // 倒计时相关变量
    let countdownInterval = null;
    let expirationTime = null;

    // 为登出链接添加点击事件监听器
    const logoutLink = document.querySelector('a[href*="logout"]');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(e) {
            // 清除localStorage中的倒计时信息
            localStorage.removeItem('serverCountdownInfo');
        });
    }

    // 安全地解析服务器数据
    // 首先尝试从HTML获取服务器数据，如果没有则通过API获取
    try {
        const serverDataElement = document.getElementById('serverData');
        if (serverDataElement && serverDataElement.dataset.servers) {
            serverData = JSON.parse(serverDataElement.dataset.servers);
            console.log('Server data loaded from data-servers attribute:', serverData);
        } else if (serverDataElement && serverDataElement.textContent) {
            const serversJson = serverDataElement.textContent.trim();
            console.log('Raw server data from textContent:', serversJson);
            serverData = JSON.parse(serversJson);
            console.log('Server data loaded from textContent:', serverData);
        } else {
            console.log('No server data found in HTML element, fetching from API');
            // 如果HTML中没有服务器数据，则通过API获取
            fetchAvailableServers();
        }
        console.log('Parsed server data:', serverData);
        console.log('Server data length:', serverData.length);
    } catch (e) {
        console.error('服务器数据解析失败:', e);
        // 如果解析失败，则通过API获取
        fetchAvailableServers();
    }

    // 检查是否有保存的倒计时信息
    checkSavedCountdownInfo();

    // 检查是否有从服务器列表页面传递过来的数据
    const selectedHost = localStorage.getItem('selectedServerHost');
    const selectedUsername = localStorage.getItem('selectedServerUsername');
    
    if (selectedHost && selectedUsername) {
        // 填充表单
        document.getElementById('targetHost').value = selectedHost;
        // 自动填充账户名选项并选择
        updateAccountOptions(accountNameSelect, selectedHost);
        document.getElementById('accountName').value = selectedUsername;
        
        // 清除localStorage中的数据
        localStorage.removeItem('selectedServerHost');
        localStorage.removeItem('selectedServerUsername');
        
        // 滚动到申请表单
        document.getElementById('applySection').scrollIntoView({ behavior: 'smooth' });
    }

    // 页面加载时检查是否有未过期的权限
    checkExistingPermissions();

    // 检查表单元素是否存在
    const applyForm = document.getElementById('applyForm');
    if (!applyForm) {
        console.error('无法找到申请表单元素 #applyForm');
    } else {
        console.log('成功找到申请表单元素');
    }

    // 主机输入事件
    targetHostInput.addEventListener('input', function () {
        const query = this.value.toLowerCase().trim();
        console.log('Input query:', query);
        console.log('Server data available:', serverData.length);
        
        if (query.length < 1) {
            hostSuggestions.classList.add('hidden');
            // 清空账户名选项
            clearAccountOptions(accountNameSelect);
            return;
        }
        
        // 确保 serverData 存在且为数组
        if (!Array.isArray(serverData) || serverData.length === 0) {
            console.log('No server data available for suggestions');
            hostSuggestions.innerHTML = '<div class="p-2 text-muted">暂无服务器数据</div>';
            hostSuggestions.classList.remove('hidden');
            // 清空账户名选项
            clearAccountOptions(accountNameSelect);
            return;
        }
        
        console.log('Server data content:', serverData);
        const matchedServers = serverData.filter(server => {
            // 确保 server 对象存在且有 host 属性
            if (!server || !server.host) {
                console.log('Invalid server object:', server);
                return false;
            }
            const hostMatch = server.host.toLowerCase().includes(query);
            const descriptionMatch = server.description && server.description.toLowerCase().includes(query);
            const usernameMatch = server.username && server.username.toLowerCase().includes(query);
            console.log(`Checking server: ${server.host}, host match: ${hostMatch}, description match: ${descriptionMatch}, username match: ${usernameMatch}`);
            return hostMatch || descriptionMatch || usernameMatch;
        }).slice(0, 5);

        console.log('Matched servers:', matchedServers);

        if (matchedServers.length > 0) {
            const fragment = document.createDocumentFragment();
            matchedServers.forEach(server => {
                const div = document.createElement('div');
                div.className = 'p-2 hover:bg-light cursor-pointer';
                div.textContent = `${server.host}:${server.port} (${server.username})${server.description ? ' - ' + server.description : ''}`;
                div.dataset.host = server.host;
                div.addEventListener('mousedown', function() {
                    targetHostInput.value = server.host;
                    // 更新并选择账户名
                    updateAccountOptions(accountNameSelect, server.host);
                    hostSuggestions.classList.add('hidden');
                });
                fragment.appendChild(div);
            });
            hostSuggestions.innerHTML = '';
            hostSuggestions.appendChild(fragment);
            hostSuggestions.classList.remove('hidden');
        } else {
            hostSuggestions.innerHTML = '<div class="p-2 text-muted">没有找到匹配的服务器</div>';
            hostSuggestions.classList.remove('hidden');
            // 清空账户名选项
            clearAccountOptions(accountNameSelect);
        }
    });

    targetHostInput.addEventListener('blur', function () {
        // 延迟隐藏，确保点击建议项时不会立即隐藏
        setTimeout(() => hostSuggestions.classList.add('hidden'), 200);
    });

    // 更新账号选项
    function updateAccountOptions(selectElement, host) {
        // 清空选项
        selectElement.innerHTML = '<option value="">请选择账号</option>';
        
        // 获取匹配的服务器账号
        const matchedServers = serverData.filter(server => server.host === host);
        
        // 添加选项
        matchedServers.forEach(server => {
            const option = document.createElement('option');
            option.value = server.username;
            option.textContent = server.username;
            option.dataset.serverId = server.id;
            selectElement.appendChild(option);
        });
        
        // 如果只有一个匹配项，自动选择
        if (matchedServers.length === 1) {
            selectElement.value = matchedServers[0].username;
        }
    }

    // 清空账号选项
    function clearAccountOptions(selectElement) {
        selectElement.innerHTML = '<option value="">请选择账号</option>';
    }

    // TOTP模态框初始化
    const totpModal = new bootstrap.Modal(document.getElementById('totpModal'));
    let applyData = null;
    let applicationId = null; // 添加申请ID变量

    // 权限申请表单提交
    document.getElementById('applyForm').addEventListener('submit', function (e) {
        e.preventDefault();
        console.log("表单提交事件触发");

        const accountName = document.getElementById('accountName').value.trim();
        const targetHost = document.getElementById('targetHost').value.trim();
        const duration = document.getElementById('duration').value;
        const reason = document.getElementById('reason').value.trim();

        if (!accountName || !targetHost || !duration) {
            alert('请填写所有必填字段');
            return;
        }

        if (!reason) {
            alert('请填写申请原因');
            return;
        }

        const matchedServer = serverData.find(server => server.host === targetHost && server.username === accountName);
        if (!matchedServer) {
            alert('缺少该服务器配置，请联系管理员添加主机信息');
            return;
        }

        // 直接提交给后端
        applyData = {
            server_id: matchedServer.id,
            account_name: accountName,
            duration: duration,
            reason: reason
        };

        fetch(window.APP_URLS.apply_permission, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify(applyData)
        })
            .then(res => res.json())
            .then(result => {
                if (result.status === 'notify_sent') {
                    console.log("钉钉通知已发送，显示 OTP 验证框");
                    applicationId = result.application_id; // 保存申请ID
                    totpModal.show();
                    // 清空申请原因
                    document.getElementById('reason').value = '';
                } else {
                    alert(result.message || "请求失败");
                }
            })
            .catch(err => {
                console.error("提交失败:", err);
                alert("提交失败，请稍后再试");
            });
    });

    // 从API获取可申请的服务器列表
    function fetchAvailableServers() {
        fetch('/api/available_servers/')
            .then(response => response.json())
            .then(result => {
                if (result.status === 'success') {
                    serverData = result.data;
                    console.log('Server data loaded from API:', serverData);
                } else {
                    console.error('获取服务器列表失败:', result.message);
                    serverData = [];
                }
            })
            .catch(error => {
                console.error('获取服务器列表时发生错误:', error);
                serverData = [];
            });
    }

    // 令牌验证通过后提交申请
    document.getElementById('verifyTotpBtn').addEventListener('click', async () => {
        console.log("OTP验证按钮被点击");
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
            const requestData = {
                token_code: totpCode,
                server_id: applyData.server_id,
                account_name: applyData.account_name,
                duration: applyData.duration
            };
            
            // 如果有申请ID，则添加到请求数据中
            if (applicationId) {
                requestData.application_id = applicationId;
            }

            const response = await fetch(window.APP_URLS.verify_otp, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify(requestData)
            });

            const result = await response.json();
            if (result.status === 'success') {
                totpModal.hide();
                document.getElementById('totpCode').value = '';

                const serverInfo = result.server_info;
                showCountdown(serverInfo);
                // 保存倒计时信息
                saveCountdownInfo(serverInfo);

                 // 弹窗提示并复制密码
                const message = `申请成功！\n服务器: ${serverInfo.host}\n用户名: ${serverInfo.username}\n有效期至: ${serverInfo.expiration}`;
                if (confirm(message + '\n\n点击确定复制密码到剪贴板')) {
                    try {
                        // 检查是否支持 Clipboard API
                        if (navigator.clipboard && window.isSecureContext) {
                            // 使用现代 Clipboard API
                            await navigator.clipboard.writeText(serverInfo.password);
                            alert('密码已复制到剪贴板');
                        } else {
                            // 使用备选的复制方法
                            fallbackCopyTextToClipboard(serverInfo.password);
                        }
                    } catch (err) {
                        console.error('复制到剪贴板失败:', err);
                        // 如果任何方法都失败，只提示用户手动复制
                        alert('复制到剪贴板失败，请手动复制密码');
                    }
                }
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

    // 传统复制方法的辅助函数
    function fallbackCopyTextToClipboard(text) {
        try {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            
            // 避免滚动到底部
            textArea.style.top = "0";
            textArea.style.left = "0";
            textArea.style.position = "fixed";
            textArea.style.opacity = "0";
            
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    alert('密码已复制到剪贴板');
                } else {
                    alert('无法自动复制密码，请手动选择并复制');
                }
            } catch (err) {
                console.error('复制失败:', err);
                alert('无法自动复制密码，请手动选择并复制');
            }
            
            document.body.removeChild(textArea);
        } catch (err) {
            console.error('创建文本区域失败:', err);
            alert('无法自动复制密码，请手动选择并复制');
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
                const response = await fetch(`${window.APP_URLS.check_server_password_expiration}?host=${encodeURIComponent(targetHost)}&username=${encodeURIComponent(accountName)}`);
                
                if (!response.ok) {
                    console.error('检查权限请求失败:', response.status);
                    return;
                }
                
                const result = await response.json();
                
                if (result.status === 'success' && result.data.has_expiration) {
                    // 显示倒计时
                    showCountdown(result.data);
                    // 保存倒计时信息
                    saveCountdownInfo(result.data);
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
            clearSavedCountdownInfo();
            return;
        }

        // 填充服务器信息
        document.getElementById('serverInfo').textContent = `${serverInfo.host}:${serverInfo.port}`;
        document.getElementById('accountInfo').textContent = `${serverInfo.username}`;
        
        // 填充申请者信息（如果有）
        if (serverInfo.applicant) {
            document.getElementById('applicantInfo').textContent = serverInfo.applicant;
        } else {
            document.getElementById('applicantInfo').textContent = '未知';
        }
        
        if (serverInfo.application_time) {
            document.getElementById('applicationTimeInfo').textContent = serverInfo.application_time;
        } else {
            document.getElementById('applicationTimeInfo').textContent = '未知';
        }

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

   // 检查是否有保存的倒计时信息
    function checkSavedCountdownInfo() {
        try {
            const savedCountdown = localStorage.getItem('serverCountdownInfo');
            if (savedCountdown) {
                const countdownInfo = JSON.parse(savedCountdown);
                const now = new Date().getTime();
                const expirationTime = new Date(countdownInfo.expiration).getTime();
                
                // 检查是否过期
                if (expirationTime > now) {
                    // 检查当前用户是否与倒计时信息中的申请者匹配
                    // 如果页面中有用户信息元素，检查用户名是否匹配
                    const userInfoElement = document.querySelector('.user-info .fw-bold');
                    if (userInfoElement) {
                        const currentUserName = userInfoElement.textContent.trim();
                        if (currentUserName === countdownInfo.applicant) {
                            // 用户匹配，显示倒计时
                            showCountdown(countdownInfo);
                        } else {
                            // 用户不匹配，清除保存的信息
                            localStorage.removeItem('serverCountdownInfo');
                        }
                    } else {
                        // 无法获取当前用户信息，默认显示倒计时（保持原有行为）
                        showCountdown(countdownInfo);
                    }
                } else {
                    // 已过期，清除保存的信息
                    localStorage.removeItem('serverCountdownInfo');
                }
            }
        } catch (e) {
            console.error('检查保存的倒计时信息失败:', e);
            localStorage.removeItem('serverCountdownInfo');
        }
    }

    // 保存倒计时信息到localStorage
    function saveCountdownInfo(serverInfo) {
        try {
            const countdownInfo = {
                host: serverInfo.host,
                port: serverInfo.port,
                username: serverInfo.username,
                expiration: serverInfo.expiration,
                applicant: serverInfo.applicant,
                application_time: serverInfo.application_time
            };
            localStorage.setItem('serverCountdownInfo', JSON.stringify(countdownInfo));
        } catch (e) {
            console.error('保存倒计时信息失败:', e);
        }
    }

    // 清除保存的倒计时信息
    function clearSavedCountdownInfo() {
        try {
            localStorage.removeItem('serverCountdownInfo');
        } catch (e) {
            console.error('清除保存的倒计时信息失败:', e);
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
            clearSavedCountdownInfo();
            return;
        }

        // 填充服务器信息
        document.getElementById('serverInfo').textContent = `${serverInfo.host}:${serverInfo.port}`;
        document.getElementById('accountInfo').textContent = `${serverInfo.username}`;
        
        // 填充申请者信息（如果有）
        if (serverInfo.applicant) {
            document.getElementById('applicantInfo').textContent = serverInfo.applicant;
        } else {
            document.getElementById('applicantInfo').textContent = '未知';
        }
        
        if (serverInfo.application_time) {
            document.getElementById('applicationTimeInfo').textContent = serverInfo.application_time;
        } else {
            document.getElementById('applicationTimeInfo').textContent = '未知';
        }

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
            
            // 清除保存的信息
            clearSavedCountdownInfo();
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
});