// 确保 navigator.clipboard 存在，如果不存在则创建一个模拟对象
(function () {
    if (typeof navigator !== 'undefined' && !navigator.clipboard) {
        navigator.clipboard = {
            writeText: function (text) {
                return new Promise(function (resolve, reject) {
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

// 在DOMContentLoaded之外也添加一个检查函数，处理页面恢复的情况
window.addEventListener('pageshow', function(event) {
    // 检查是否是从缓存中加载的页面
    if (event.persisted) {
        console.log("页面从缓存中恢复");
        // 延迟执行检查，确保DOM已完全加载
        setTimeout(function() {
            if (typeof checkSavedCountdownInfo === 'function') {
                checkSavedCountdownInfo();
            }
        }, 100);
    }
});

document.addEventListener('DOMContentLoaded', function () {
    // 自动完成
    const targetHostInput = document.getElementById('targetHost');
    const hostSuggestions = document.getElementById('hostSuggestions');
    const accountNameSelect = document.getElementById('accountName');
    let serverData = [];
    
    // 获取密码显示配置（在 DOMContentLoaded 事件中添加）
    const passwordDisplayMode = window.PASSWORD_CONFIG ? window.PASSWORD_CONFIG.display_mode : 'auto_copy';
    const modalDisplayDuration = window.PASSWORD_CONFIG ? window.PASSWORD_CONFIG.modal_display_duration : 3;

    // 添加调试信息
    console.log("密码显示配置:", {
        passwordDisplayMode: passwordDisplayMode,
        modalDisplayDuration: modalDisplayDuration,
        PASSWORD_CONFIG: window.PASSWORD_CONFIG
    });
    
    // 密码隐藏定时器
    let passwordHideTimer = null;
    let applyData = null;
    let applicationId = null;

    // 倒计时相关变量
    let countdownInterval = null;
    let expirationTime = null;

    // 为登出链接添加点击事件监听器
    const logoutLink = document.querySelector('a[href*="logout"]');
    if (logoutLink) {
        logoutLink.addEventListener('click', function (e) {
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

    // 检查是否有保存的倒计时信息（在所有初始化完成后立即检查）
    setTimeout(checkSavedCountdownInfo, 0);

    // 检查是否有从服务器列表页面传递过来的数据
    const selectedHost = localStorage.getItem('selectedServerHost');
    const selectedUsername = localStorage.getItem('selectedServerUsername');

    if (selectedHost && selectedUsername) {
        // 等待serverData加载完成后再处理
        const processServerSelection = () => {
            if (serverData && serverData.length > 0) {
                // 填充表单
                document.getElementById('targetHost').value = selectedHost;

                // 更新账户名选项
                updateAccountOptions(accountNameSelect, selectedHost);

                // 确保选中正确的账户名
                setTimeout(() => {
                    document.getElementById('accountName').value = selectedUsername;
                }, 10);

                // 清除localStorage中的数据
                localStorage.removeItem('selectedServerHost');
                localStorage.removeItem('selectedServerUsername');

                // 滚动到申请表单
                document.getElementById('applySection').scrollIntoView({ behavior: 'smooth' });
            } else {
                // 如果数据还没加载完成，稍后再试
                setTimeout(processServerSelection, 100);
            }
        };

        processServerSelection();
    }

    // 页面加载时检查是否有未过期的权限
    setTimeout(checkExistingPermissions, 100);

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
                div.addEventListener('mousedown', function () {
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

            // 当只有一个匹配项时，自动更新账户名选项
            if (matchedServers.length === 1) {
                updateAccountOptions(accountNameSelect, matchedServers[0].host);
            }
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

        // 确保 serverData 存在且为数组
        if (!Array.isArray(serverData) || serverData.length === 0) {
            console.log('No server data available for account options');
            return;
        }

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

    // 从API获取可申请的服务器列表
    function fetchAvailableServers() {
        fetch('/api/available_servers/')
            .then(response => response.json())
            .then(result => {
                if (result.status === 'success') {
                    serverData = result.data;
                    console.log('Server data loaded from API:', serverData);

                    // 如果有从服务器列表页面传递过来的数据，现在处理它
                    const selectedHost = localStorage.getItem('selectedServerHost');
                    const selectedUsername = localStorage.getItem('selectedServerUsername');

                    if (selectedHost && selectedUsername) {
                        // 填充表单
                        document.getElementById('targetHost').value = selectedHost;

                        // 更新账户名选项
                        updateAccountOptions(accountNameSelect, selectedHost);

                        // 确保选中正确的账户名
                        setTimeout(() => {
                            document.getElementById('accountName').value = selectedUsername;
                        }, 10);

                        // 清除localStorage中的数据
                        localStorage.removeItem('selectedServerHost');
                        localStorage.removeItem('selectedServerUsername');

                        // 滚动到申请表单
                        document.getElementById('applySection').scrollIntoView({ behavior: 'smooth' });
                    }
                    
                    // 服务器数据加载完成后，再次检查保存的倒计时信息
                    // 这样可以确保在显示倒计时时能够正确处理服务器相关信息
                    setTimeout(checkSavedCountdownInfo, 100);
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

    // 通用复制文本函数
    function copyTextToClipboard(text) {
        // 检查是否支持 Clipboard API
        if (navigator.clipboard && window.isSecureContext) {
            // 使用现代 Clipboard API
            navigator.clipboard.writeText(text).then(() => {
                alert('已复制到剪贴板');
            }).catch(err => {
                console.error('复制失败:', err);
                fallbackCopyTextToClipboard(text);
            });
        } else {
            // 使用备选的复制方法
            fallbackCopyTextToClipboard(text);
        }
    }

    // 切换密码可见性
    function togglePasswordVisibility() {
        const passwordField = document.getElementById('passwordValue');
        const toggleBtn = document.getElementById('togglePasswordBtn');
        
        if (passwordField.type === 'password') {
            // 显示密码
            passwordField.type = 'text';
            passwordField.value = window.currentPassword; // 使用存储的密码
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash me-1"></i>隐藏';
            document.getElementById('copyPasswordFromSectionBtn').disabled = false;
            
            // 启动自动隐藏计时器
            startPasswordHideTimer(modalDisplayDuration, passwordField);
        } else {
            // 隐藏密码
            passwordField.type = 'password';
            passwordField.value = '••••••••';
            toggleBtn.innerHTML = '<i class="fas fa-eye me-1"></i>显示';
            document.getElementById('copyPasswordFromSectionBtn').disabled = true;
            
            // 清除计时器
            if (passwordHideTimer) {
                clearTimeout(passwordHideTimer);
                passwordHideTimer = null;
            }
        }
    }

    // 启动密码隐藏计时器
    function startPasswordHideTimer(duration, passwordField) {
        if (passwordHideTimer) {
            clearTimeout(passwordHideTimer);
        }

        // 更新倒计时显示
        let timeLeft = duration;
        const timerElement = document.getElementById('passwordTimer');
        const countdownElement = document.getElementById('passwordCountdownTimer');

        const timer = setInterval(() => {
            timeLeft--;
            timerElement.textContent = timeLeft;
            countdownElement.textContent = timeLeft;

            if (timeLeft <= 0) {
                clearInterval(timer);
                // 隐藏密码
                passwordField.type = 'password';
                passwordField.value = '••••••••';
                document.getElementById('togglePasswordBtn').innerHTML = '<i class="fas fa-eye me-1"></i>显示';
                document.getElementById('copyPasswordFromSectionBtn').disabled = true;
                document.getElementById('passwordVisibilityWarning').innerHTML =
                    '<span class="text-danger">密码已隐藏，点击显示按钮可再次查看</span>';
            }
        }, 1000);
        
        passwordHideTimer = timer;
    }

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
                    // 根据配置决定如何显示密码信息
                    if (passwordDisplayMode === 'manual') {
                        // 在manual模式下，我们需要显示倒计时和密码区域
                        showCountdownWithPassword(result.data);
                    } else {
                        // 显示倒计时
                        showCountdown(result.data);
                    }
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
        console.log("显示倒计时信息:", serverInfo);
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
    // 显示倒计时和密码区域（用于manual模式）
    function showCountdownWithPassword(serverInfo) {
        console.log("在手动模式下显示倒计时和密码信息:", serverInfo);
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
            // 如果没有申请者信息，尝试从用户信息中获取
            const userInfoElement = document.querySelector('.user-info .fw-bold');
            if (userInfoElement) {
                document.getElementById('applicantInfo').textContent = userInfoElement.textContent.trim();
            } else {
                document.getElementById('applicantInfo').textContent = '未知';
            }
        }

        if (serverInfo.application_time) {
            document.getElementById('applicationTimeInfo').textContent = serverInfo.application_time;
        } else {
            document.getElementById('applicationTimeInfo').textContent = new Date().toLocaleString('zh-CN');
        }
        
        // 添加密码显示区域（如果尚未添加）
        const countdownDisplay = document.getElementById('countdownDisplay');
        const passwordAreaExists = document.getElementById('mainPasswordValue');
        
        if (!passwordAreaExists) {
            // 添加密码显示区域
            const passwordArea = `
                <div class="server-info-box mt-3">
                    <div class="row align-items-center">
                        <div class="col-md-8 mb-3 mb-md-0">
                            <div class="server-info-label"><i class="fas fa-lock me-2"></i>临时密码</div>
                            <div class="input-group">
                                <input type="password" class="form-control" id="mainPasswordValue" value="••••••••" readonly style="font-family: monospace;">
                                <button class="btn btn-outline-secondary" type="button" id="mainTogglePasswordBtn" title="按住显示密码">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-outline-primary" type="button" id="mainCopyPasswordBtn" title="复制密码到剪贴板">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <div class="form-text mt-1">按住<i class="fas fa-eye ms-1 me-1"></i>图标显示密码，松开即隐藏</div>
                        </div>
                        <div class="col-md-4">
                            <div class="alert alert-info mb-0 py-2">
                                <i class="fas fa-info-circle me-1"></i>
                                <small>密码有效期结束后将自动重置</small>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // 插入密码区域到倒计时区域中（在倒计时显示之前）
            countdownDisplay.insertAdjacentHTML('beforebegin', passwordArea);
            
            // 添加事件监听器
            setTimeout(function() {
                const toggleBtn = document.getElementById('mainTogglePasswordBtn');
                const passwordField = document.getElementById('mainPasswordValue');
                const copyBtn = document.getElementById('mainCopyPasswordBtn');
                
                if (toggleBtn && passwordField && copyBtn) {
                    // 按住显示，松开隐藏
                    toggleBtn.addEventListener('mousedown', function() {
                        passwordField.type = 'text';
                        passwordField.value = window.currentPassword || serverInfo.password; // 使用保存的密码或从serverInfo获取
                        toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
                        toggleBtn.title = "松开隐藏密码";
                    });
                    
                    toggleBtn.addEventListener('mouseup', function() {
                        passwordField.type = 'password';
                        passwordField.value = '••••••••';
                        toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
                        toggleBtn.title = "按住显示密码";
                    });
                    
                    toggleBtn.addEventListener('mouseleave', function() {
                        // 鼠标离开按钮时也隐藏密码
                        passwordField.type = 'password';
                        passwordField.value = '••••••••';
                        toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
                        toggleBtn.title = "按住显示密码";
                    });
                    
                    // 对于触摸设备，添加触摸事件支持
                    toggleBtn.addEventListener('touchstart', function(e) {
                        e.preventDefault();
                        passwordField.type = 'text';
                        passwordField.value = window.currentPassword || serverInfo.password; // 使用保存的密码或从serverInfo获取
                        toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
                        toggleBtn.title = "松开隐藏密码";
                    });
                    
                    toggleBtn.addEventListener('touchend', function(e) {
                        e.preventDefault();
                        passwordField.type = 'password';
                        passwordField.value = '••••••••';
                        toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
                        toggleBtn.title = "按住显示密码";
                    });
                    
                    // 复制按钮事件
                    copyBtn.addEventListener('click', function() {
                        // 无论密码是否可见，都复制真实密码
                        copyTextToClipboard(window.currentPassword || serverInfo.password);
                    });
                }
            }, 100);
        } else {
            // 如果密码区域已存在，更新密码值
            const passwordField = document.getElementById('mainPasswordValue');
            if (passwordField) {
                passwordField.type = 'password';
                passwordField.value = '••••••••';
            }
            
            // 更新按钮状态
            const toggleBtn = document.getElementById('mainTogglePasswordBtn');
            if (toggleBtn) {
                toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
                toggleBtn.title = "按住显示密码";
            }
            
            const copyBtn = document.getElementById('mainCopyPasswordBtn');
            if (copyBtn) {
                copyBtn.disabled = true;
            }
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

    // 页面隐藏时的处理
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            console.log("页面隐藏，暂停倒计时");
            // 页面隐藏时暂停倒计时
            if (countdownInterval) {
                clearInterval(countdownInterval);
                countdownInterval = null;
            }
        } else {
            console.log("页面显示，恢复倒计时");
            // 页面显示时恢复倒计时
            if (expirationTime) {
                startCountdown();
            }
        }
    });

    // 页面焦点改变时的处理
    window.addEventListener('focus', function() {
        console.log("页面获得焦点，检查倒计时信息");
        setTimeout(checkSavedCountdownInfo, 100);
    });

    // 页面卸载时清除倒计时
    window.addEventListener('beforeunload', function () {
        console.log("页面即将卸载，保存倒计时状态");
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
    });
    // 检查是否有保存的倒计时信息
    function checkSavedCountdownInfo() {
        try {
            console.log("检查保存的倒计时信息");
            const savedCountdown = localStorage.getItem('serverCountdownInfo');
            if (savedCountdown) {
                console.log("找到保存的倒计时信息:", savedCountdown);
                const countdownInfo = JSON.parse(savedCountdown);
                const now = new Date().getTime();
                const expirationTime = new Date(countdownInfo.expiration).getTime();

                // 检查是否过期
                if (expirationTime > now) {
                    console.log("倒计时信息未过期，显示倒计时区域");
                    // 检查当前用户是否与倒计时信息中的申请者匹配
                    // 如果页面中有用户信息元素，检查用户名是否匹配
                    const userInfoElement = document.querySelector('.user-info .fw-bold');
                    if (userInfoElement) {
                        const currentUserName = userInfoElement.textContent.trim();
                        console.log("当前用户:", currentUserName, "申请者:", countdownInfo.applicant);
                        if (currentUserName === countdownInfo.applicant) {
                            // 用户匹配，显示倒计时
                            // 根据配置决定如何显示密码信息
                            if (passwordDisplayMode === 'manual') {
                                // 保存密码信息
                                window.currentPassword = countdownInfo.password;
                                showCountdownWithPassword(countdownInfo);
                            } else {
                                showCountdown(countdownInfo);
                            }
                        } else {
                            // 用户不匹配，清除保存的信息
                            console.log("用户不匹配，清除保存的信息");
                            localStorage.removeItem('serverCountdownInfo');
                        }
                    } else {
                        // 无法获取当前用户信息，但仍显示倒计时（因为这是返回页面的情况）
                        console.log("无法获取当前用户信息，但仍显示倒计时");
                        // 根据配置决定如何显示密码信息
                        if (passwordDisplayMode === 'manual') {
                            // 保存密码信息
                            window.currentPassword = countdownInfo.password;
                            showCountdownWithPassword(countdownInfo);
                        } else {
                            showCountdown(countdownInfo);
                        }
                    }
                } else {
                    // 已过期，清除保存的信息
                    console.log("倒计时信息已过期，清除保存的信息");
                    localStorage.removeItem('serverCountdownInfo');
                }
            } else {
                console.log("未找到保存的倒计时信息");
            }
        } catch (e) {
            console.error('检查保存的倒计时信息失败:', e);
            localStorage.removeItem('serverCountdownInfo');
        }
    }

    // 保存倒计时信息到localStorage
    function saveCountdownInfo(serverInfo) {
        try {
            // 获取当前用户信息
            const userInfoElement = document.querySelector('.user-info .fw-bold');
            const currentUser = userInfoElement ? userInfoElement.textContent.trim() : '未知用户';
            
            const countdownInfo = {
                host: serverInfo.host,
                port: serverInfo.port,
                username: serverInfo.username,
                expiration: serverInfo.expiration,
                applicant: serverInfo.applicant || currentUser,
                application_time: serverInfo.application_time || new Date().toLocaleString('zh-CN'),
                password: serverInfo.password // 保存密码信息
            };
            console.log("保存倒计时信息到localStorage:", countdownInfo);
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

    // 表单提交事件
    document.getElementById('applyForm').addEventListener('submit', async function (e) {
        e.preventDefault();
        console.log("表单提交事件被触发");

        const targetHost = document.getElementById('targetHost').value.trim();
        const accountName = document.getElementById('accountName').value.trim();
        const duration = parseFloat(document.getElementById('duration').value);
        const reason = document.getElementById('reason').value.trim();

        console.log("表单数据:", { targetHost, accountName, duration, reason });

        if (!targetHost || !accountName || !duration || !reason) {
            alert('请填写所有必填字段');
            return;
        }

        // 获取选中的服务器ID
        const selectedOption = document.getElementById('accountName').selectedOptions[0];
        const serverId = selectedOption ? selectedOption.dataset.serverId : null;

        if (!serverId) {
            alert('未能找到服务器信息，请重新选择');
            return;
        }

        const submitBtn = document.getElementById('submitBtn');
        const submitText = document.getElementById('submitText');
        const originalText = submitText.textContent;

        // 禁用提交按钮并显示加载状态
        submitBtn.disabled = true;
        submitText.innerHTML = '<span class="loading"></span> 提交中...';

        try {
            // 准备申请数据
            applyData = {
                server_id: parseInt(serverId),
                account_name: accountName,
                duration: duration
            };

            console.log("准备发送申请数据:", applyData);

            // 发送申请请求
            const response = await fetch(window.APP_URLS.apply_permission, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({
                    server_id: parseInt(serverId),
                    account_name: accountName,
                    duration: duration,
                    reason: reason
                })
            });

            const result = await response.json();
            console.log("申请响应:", result);

            if (result.status === 'notify_sent') {
                // 显示TOTP模态框
                applicationId = result.application_id;
                const totpModal = new bootstrap.Modal(document.getElementById('totpModal'));
                totpModal.show();
                document.getElementById('totpCode').focus();
            } else {
                alert(result.message || '申请提交失败');
            }
        } catch (error) {
            console.error('申请过程中发生错误:', error);
            alert('申请过程中发生错误，请稍后重试');
        } finally {
            // 恢复提交按钮状态
            submitBtn.disabled = false;
            submitText.textContent = originalText;
        }
    });

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
                server_id: applyData ? applyData.server_id : null,
                account_name: applyData ? applyData.account_name : null,
                duration: applyData ? applyData.duration : null
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
            console.log("OTP验证响应结果:", result);
            if (result.status === 'success') {
                const totpModal = bootstrap.Modal.getInstance(document.getElementById('totpModal'));
                totpModal.hide();
                document.getElementById('totpCode').value = '';

                const serverInfo = result.server_info;
                console.log("OTP验证成功，密码显示模式：", passwordDisplayMode);

                // 根据配置决定密码显示方式
                if (passwordDisplayMode === 'auto_copy') {
                    console.log("使用自动复制模式");

                    // 自动复制到剪贴板方式
                    showCountdown(serverInfo);
                    // 保存倒计时信息
                    saveCountdownInfo(serverInfo);

                    // 弹窗提示并复制密码
                    const message = `申请成功！\n服务器: ${serverInfo.host}\n用户名: ${serverInfo.username}\n有效期至: ${serverInfo.expiration}`;
                    if (confirm(message + '\n\n点击确定复制密码到剪贴板')) {
                        copyTextToClipboard(serverInfo.password);
                    }
                } else if (passwordDisplayMode === 'manual') {
                    console.log("使用手动显示模式");
                    // 手动显示模式 - 在倒计时区域显示密码
                    // 保存当前密码供后续使用
                    window.currentPassword = serverInfo.password;
                    showCountdownWithPassword(serverInfo);
                    // 保存倒计时信息
                    saveCountdownInfo(serverInfo);
                }
            } else {
                alert(result.message || '验证失败');
            }
        } catch (error) {
            console.error('验证OTP时发生错误:', error);
            alert('验证过程中发生错误，请稍后重试');
        } finally {
            // 恢复按钮状态
            verifyBtn.innerHTML = originalText;
            verifyBtn.disabled = false;
        }
    });
});