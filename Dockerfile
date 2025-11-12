FROM registry.cn-hangzhou.aliyuncs.com/eddy-his/server-management:v1.3

# 设置工作目录
WORKDIR /app

# 复制项目文件
COPY . /app/sever_management/

# 暴露端口
EXPOSE 8000

# 运行应用
CMD python manage.py runserver 0.0.0.0:8000
