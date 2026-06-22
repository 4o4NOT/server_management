FROM registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.3

# 设置工作目录
WORKDIR /app

RUN rm -rf *

# 复制项目文件
COPY . /app

# 配置 pip 国内镜像源（阿里云）
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 收集静态文件
RUN python manage.py collectstatic --noinput

# 创建日志目录
RUN mkdir -p /app/logs

# 暴露端口
EXPOSE 8000

# 使用 gunicorn 启动（生产级 WSGI 服务器）
# --workers 4: 4个worker进程（多核利用）
# --timeout 120: 请求超时120秒
# --access-logfile: 访问日志
CMD gunicorn server_management.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --timeout 120 \
    --access-logfile /app/logs/gunicorn_access.log \
    --error-logfile /app/logs/gunicorn_error.log
