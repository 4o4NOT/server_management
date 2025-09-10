from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from cryptography.fernet import Fernet
import base64
import os

class UserInfoManager(BaseUserManager):
    """自定义用户管理器"""

    def create_user(self, user_name, phone, password=None, **extra_fields):
        """
        创建普通用户
        :param user_name: 用户名
        :param phone: 手机号
        :param password: 密码
        :param extra_fields: 额外字段
        :return: 用户对象
        """
        if not user_name:
            raise ValueError('用户名不能为空')
        if not phone:
            raise ValueError('手机号不能为空')

        user = self.model(
            user_name=user_name,
            phone=phone,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, user_name, phone, password=None, **extra_fields):
        """
        创建超级用户
        :param user_name: 用户名
        :param phone: 手机号
        :param password: 密码
        :param extra_fields: 额外字段
        :return: 超级用户对象
        """
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(user_name, phone, password, **extra_fields)


class UserInfo(AbstractBaseUser, PermissionsMixin):
    """自定义用户模型"""

    user_name = models.CharField(verbose_name='用户名', max_length=20, unique=True)
    phone = models.CharField(verbose_name='手机号', max_length=11, unique=True)
    password = models.CharField(verbose_name='密码', max_length=128)
    is_superuser = models.BooleanField(verbose_name='是否超级用户', default=False)
    is_active = models.BooleanField(verbose_name='是否激活', default=True)
    last_login = models.DateTimeField(verbose_name='最后登录时间', null=True, blank=True)
    date_joined = models.DateTimeField(verbose_name='注册时间', default=timezone.now)

    # OTP相关字段
    otp_secret = models.CharField(
        verbose_name='OTP密钥',
        max_length=32,
        blank=True,
        null=True,
        help_text='用于生成OTP验证码的密钥'
    )
    otp_active = models.BooleanField(
        verbose_name='OTP是否激活',
        default=False,
        help_text='标记用户是否已完成OTP绑定'
    )

    class Meta:
        db_table = "user_info"  # 自定义表名
        verbose_name = '用户信息'
        verbose_name_plural = '用户信息'

    # 设置用户名字段
    USERNAME_FIELD = 'user_name'
    REQUIRED_FIELDS = ['phone']

    objects = UserInfoManager()

    def __str__(self):
        return self.user_name

    @property
    def is_staff(self):
        """是否是员工（管理员）"""
        return self.is_superuser

# 简化的密码加密类，使用Django SECRET_KEY
class SimplePasswordCrypto:
    def __init__(self):
        from django.conf import settings
        # 使用Django SECRET_KEY作为基础，生成适合Fernet的32字节密钥
        secret_key = settings.SECRET_KEY.encode('utf-8')
        # 通过哈希确保长度为32字节
        key = base64.urlsafe_b64encode(secret_key[:32].ljust(32, b'0'))
        self.cipher = Fernet(key)
    
    def encrypt(self, password):
        """加密密码"""
        if not password:
            return ""
        if isinstance(password, str):
            password = password.encode('utf-8')
        return self.cipher.encrypt(password).decode('utf-8')
    
    def decrypt(self, encrypted_password):
        """解密密码"""
        if not encrypted_password:
            return ""
        if isinstance(encrypted_password, str):
            encrypted_password = encrypted_password.encode('utf-8')
        try:
            return self.cipher.decrypt(encrypted_password).decode('utf-8')
        except Exception:
            # 如果解密失败，可能是因为使用了旧的加密方式
            return encrypted_password

# 创建全局加密实例
password_crypto = SimplePasswordCrypto()


class ServerInfo(models.Model):
    """服务器信息模型"""

    host = models.CharField(
        verbose_name='主机地址',
        max_length=100,
        help_text='服务器IP地址或域名'
    )
    port = models.IntegerField(
        verbose_name='端口',
        default=22,
        help_text='SSH连接端口，默认22'
    )
    username = models.CharField(
        verbose_name='用户名',
        max_length=50,
        help_text='服务器登录用户名'
    )
    password = models.CharField(
        verbose_name='密码',
        max_length=255,
        help_text='服务器登录密码（已加密）'
    )
    description = models.TextField(
        verbose_name='描述',
        blank=True,
        help_text='服务器用途或备注信息'
    )
    last_password_change = models.DateTimeField(
        verbose_name='最后密码修改时间',
        default=timezone.now,
        help_text='记录密码最后一次修改的时间'
    )
    current_duration = models.IntegerField(
        verbose_name='当前密码有效期（小时）',
        default=0,
        help_text='当前密码的有效期，以小时为单位'
    )
    # 添加存储生成密码的字段
    generated_password = models.CharField(
        verbose_name='生成的密码',
        max_length=128,
        blank=True,
        null=True,
        help_text='为用户生成的临时密码'
    )
    password_expiration_time = models.DateTimeField(
        verbose_name='密码过期时间',
        blank=True,
        null=True,
        help_text='生成密码的过期时间'
    )

    class Meta:
        db_table = "server_info"
        verbose_name = '服务器信息'
        verbose_name_plural = '服务器信息'
        ordering = ['-last_password_change']
        # 添加唯一性约束，确保同一主机和用户名组合不重复
        unique_together = ('host', 'username')

    def __str__(self):
        return f"{self.username}@{self.host}:{self.port}"
    
    def set_password(self, raw_password):
        """设置并加密密码"""
        self.password = password_crypto.encrypt(raw_password)
    
    def get_password(self):
        """获取解密后的密码"""
        return password_crypto.decrypt(self.password)
    
class PermissionApplication(models.Model):
    """权限申请记录模型"""
    
    STATUS_CHOICES = [
        ('pending', '待处理'),
        ('verification_pending', '待验证'),
        ('verification_failed', '验证失败'),
        ('approved', '已批准'),
        ('rejected', '已拒绝'),
        ('expired', '已过期'),
    ]
    
    applicant = models.ForeignKey(
        UserInfo,
        on_delete=models.CASCADE,
        verbose_name='申请人',
        related_name='permission_applications'
    )
    server = models.ForeignKey(
        ServerInfo,
        on_delete=models.CASCADE,
        verbose_name='目标服务器'
    )
    account_name = models.CharField(
        verbose_name='账户名',
        max_length=50,
        help_text='申请访问的账户名'
    )
    reason = models.TextField(
        verbose_name='申请原因',
        help_text='申请权限的原因说明'
    )
    duration = models.IntegerField(
        verbose_name='申请时长（小时）',
        help_text='申请的权限有效期，以小时为单位'
    )
    status = models.CharField(
        verbose_name='申请状态',
        max_length=30,
        choices=STATUS_CHOICES,
        default='pending'
    )
    applied_at = models.DateTimeField(
        verbose_name='申请时间',
        default=timezone.now
    )
    approved_at = models.DateTimeField(
        verbose_name='批准时间',
        null=True,
        blank=True
    )
    expired_at = models.DateTimeField(
        verbose_name='过期时间',
        null=True,
        blank=True
    )
    
    # 新增字段以更好地记录权限申请流程
    verification_attempts = models.IntegerField(
        verbose_name='验证尝试次数',
        default=0,
        help_text='OTP验证尝试次数'
    )
    last_verification_attempt = models.DateTimeField(
        verbose_name='最后验证尝试时间',
        null=True,
        blank=True,
        help_text='最后一次OTP验证尝试的时间'
    )
    verification_code_sent = models.BooleanField(
        verbose_name='验证码已发送',
        default=False,
        help_text='标记是否已发送OTP验证码'
    )
    verification_code_sent_at = models.DateTimeField(
        verbose_name='验证码发送时间',
        null=True,
        blank=True,
        help_text='OTP验证码发送的时间'
    )
    
    class Meta:
        db_table = "permission_application"
        verbose_name = '权限申请记录'
        verbose_name_plural = '权限申请记录'
        ordering = ['-applied_at']
    
    def __str__(self):
        return f"{self.applicant.user_name} 申请访问 {self.server.host}"
    
    def save(self, *args, **kwargs):
        # 如果是新记录且状态为待处理，计算过期时间
        if self.status == 'pending' and not self.expired_at:
            self.expired_at = self.applied_at + timezone.timedelta(hours=self.duration)
        super().save(*args, **kwargs)