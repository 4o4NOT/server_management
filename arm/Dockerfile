FROM python:3.12-alpine

# 设置清华源（Alpine）
RUN echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.22/main" > /etc/apk/repositories && \
    echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.22/community" >> /etc/apk/repositories

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apk add --no-cache \
    mariadb-connector-c-dev \
    build-base \
    pkgconfig \
    linux-headers \
    libffi-dev \
    openssl-dev \
    zlib-dev \
    jpeg-dev

# 复制项目文件
COPY . /app

# 安装 Python 依赖
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 暴露端口
EXPOSE 8000

# 运行应用
CMD python manage.py runserver 0.0.0.0:8000