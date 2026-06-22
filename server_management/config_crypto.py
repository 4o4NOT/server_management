"""
配置文件透明加密模块

在程序首次启动时自动将 config.ini / .env 中的敏感值替换为
ENC:<ciphertext> 格式的密文，后续启动自动解密。上层代码无感知。

加密主密钥来源（优先级从高到低）：
  1. 环境变量 CONFIG_MASTER_KEY（32 字节 URL-safe base64）
  2. 机器指纹 SHA256(hostname + 项目根路径)  →  配置绑定当前机器

零 Django 依赖，确保在 settings.py 加载前即可正常工作。
"""

import os
import re
import socket
import hashlib
import base64
import logging
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# ── 常量 ────────────────────────────────────────────────
ENC_PREFIX = "ENC:"

# 需要透明加密的 config.ini (section_lower, key_lower) 集合
_SENSITIVE_INI_KEYS = {
    ("database", "password"),
    ("dingtalk", "webhook_url"),
    ("dingtalk", "app_key"),
    ("dingtalk", "app_secret"),
    ("security", "secret_key"),
}

# .env 文件中对应的敏感环境变量名（大写）
_SENSITIVE_ENV_VARS = {
    "DB_PASSWORD",
    "DJANGO_SECRET_KEY",
    "DINGTALK_WEBHOOK_URL",
    "DINGTALK_APP_KEY",
    "DINGTALK_APP_SECRET",
}

# 项目根目录（config_crypto.py 位于 server_management/ 下）
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)

# ── 加密原语 ────────────────────────────────────────────

def _derive_master_key() -> bytes:
    """
    派生 32 字节 Fernet-compatible 密钥 (URL-safe base64 编码)。

    优先级：
      1. 环境变量 CONFIG_MASTER_KEY（32 字节 base64）
      2. SHA-256(hostname + 项目根路径)
    """
    master_key_env = os.environ.get("CONFIG_MASTER_KEY")
    if master_key_env:
        try:
            decoded = base64.urlsafe_b64decode(master_key_env.encode("utf-8"))
            if len(decoded) == 32:
                logger.info("使用 CONFIG_MASTER_KEY 作为配置加密主密钥")
                return master_key_env.encode("utf-8")
            else:
                logger.warning("CONFIG_MASTER_KEY 长度不是 32 字节，回退到机器指纹")
        except Exception as e:
            logger.warning("CONFIG_MASTER_KEY 格式无效 (%s)，回退到机器指纹", e)

    # 机器指纹
    try:
        machine_id = socket.gethostname()
    except Exception:
        machine_id = "unknown-host"

    fingerprint = hashlib.sha256(
        (machine_id + _PROJECT_ROOT).encode("utf-8")
    ).digest()
    key = base64.urlsafe_b64encode(fingerprint)
    logger.debug("使用机器指纹派生配置加密密钥 (hostname=%s)", machine_id)
    return key


def _get_cipher() -> Fernet:
    """获取 Fernet 加解密实例"""
    return Fernet(_derive_master_key())


# ── 公共 API ────────────────────────────────────────────

def is_encrypted(value: str) -> bool:
    """检查值是否已加密（以 ENC: 开头）"""
    return isinstance(value, str) and value.startswith(ENC_PREFIX)


def encrypt_value(value: str) -> str:
    """
    加密明文值，返回 "ENC:<ciphertext>"。
    空值或已加密值直接返回原值。
    """
    if not value:
        return value
    if is_encrypted(value):
        return value
    cipher = _get_cipher()
    encrypted = cipher.encrypt(value.encode("utf-8"))
    return ENC_PREFIX + encrypted.decode("utf-8")


def decrypt_value(value: str) -> str:
    """
    解密可能已加密的值。

    - 有 ENC: 前缀  → 解密返回明文
    - 无前缀        → 直接返回
    - 解密失败      → 返回原始 ENC:... 值（优雅降级）
    """
    if not value:
        return value
    if not is_encrypted(value):
        return value
    ciphertext = value[len(ENC_PREFIX):]
    try:
        cipher = _get_cipher()
        return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("配置值解密失败：密钥不匹配（可能配置文件来自其他机器）")
        return value
    except Exception as e:
        logger.warning("配置值解密失败: %s", e)
        return value


def get_sensitive_keys():
    """返回需要加密的 config.ini 敏感键集合"""
    return _SENSITIVE_INI_KEYS.copy()


def get_sensitive_env_vars():
    """返回需要加密的 .env 敏感变量名集合"""
    return _SENSITIVE_ENV_VARS.copy()


# ── config.ini 处理 ─────────────────────────────────────

def _rewrite_value_in_lines(lines, section, key, old_value, new_value):
    """
    在原始文件行数组中替换指定键的值。

    用大小写不敏感匹配 [section] 头和 key = value 行，
    保留原有缩进、空格和注释。
    """
    section_pattern = re.compile(
        r'^\s*\[\s*' + re.escape(section) + r'\s*\]\s*$', re.IGNORECASE
    )
    key_pattern = re.compile(
        r'^(\s*' + re.escape(key) + r'\s*[=:]\s*)(.*?)(\s*)$', re.IGNORECASE
    )

    in_target = False
    for i, line in enumerate(lines):
        if section_pattern.match(line):
            in_target = True
            continue
        if in_target and line.strip().startswith("["):
            in_target = False
            continue
        if not in_target:
            continue

        m = key_pattern.match(line)
        if m:
            current_val = m.group(2).strip()
            if current_val == old_value.strip():
                lines[i] = m.group(1) + new_value + m.group(3) + "\n"
                return


def _process_ini_file(config_path, sensitive_keys):
    """
    扫描 config.ini，将明文敏感值替换为 ENC:<ciphertext>，
    以原子方式写回文件。

    sensitive_keys: {(section_lower, key_lower), ...}

    返回: {(section_lower, key_lower): decrypted_plaintext}
    """
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 同时用 configparser 解析，方便查找 section/key 的实际大小写
    import configparser
    config = configparser.RawConfigParser()
    config.read(config_path, encoding="utf-8")

    decrypted_values = {}
    needs_rewrite = False

    for section_lower, key_lower in sensitive_keys:
        # 查找实际大小写的 section
        actual_section = None
        for s in config.sections():
            if s.lower() == section_lower:
                actual_section = s
                break
        if actual_section is None:
            continue

        # 查找实际大小写的 key
        actual_key = None
        for k in config.options(actual_section):
            if k.lower() == key_lower:
                actual_key = k
                break
        if actual_key is None:
            continue

        raw_value = config.get(actual_section, actual_key)

        if not raw_value or not raw_value.strip():
            decrypted_values[(section_lower, key_lower)] = ""
            continue

        if is_encrypted(raw_value):
            # 已加密 → 解密缓存
            decrypted = decrypt_value(raw_value)
            decrypted_values[(section_lower, key_lower)] = decrypted
        else:
            # 明文 → 加密并回写
            encrypted = encrypt_value(raw_value)
            decrypted_values[(section_lower, key_lower)] = raw_value
            needs_rewrite = True
            _rewrite_value_in_lines(
                lines, actual_section, actual_key, raw_value, encrypted
            )

    if needs_rewrite:
        temp_path = config_path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            os.replace(temp_path, config_path)
            logger.info("已自动加密 config.ini 中的敏感值")
        except Exception as e:
            logger.error("写入加密后的 config.ini 失败: %s", e)
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return decrypted_values


# ── .env 文件处理 ────────────────────────────────────────

def _load_dotenv(dotenv_path):
    """
    解析 .env 文件，返回 {VAR_NAME: value} dict。
    不修改 os.environ，不覆盖已有环境变量。
    支持: KEY=value, KEY="value", KEY='value', export KEY=value, # 注释
    """
    result = {}
    if not os.path.exists(dotenv_path):
        return result

    with open(dotenv_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # 去除 export 前缀
            stripped = re.sub(r'^export\s+', '', stripped, flags=re.IGNORECASE)
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', stripped)
            if not m:
                continue
            key = m.group(1)
            value = m.group(2).strip()
            # 去除引号
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            result[key] = value
    return result


def _process_dotenv_file(dotenv_path, sensitive_env_vars):
    """
    扫描 .env 文件，将明文敏感值替换为 ENC:<ciphertext>，
    以原子方式写回。

    sensitive_env_vars: {"DB_PASSWORD", "DJANGO_SECRET_KEY", ...}

    返回: {ENV_VAR_NAME: decrypted_plaintext}
    """
    if not os.path.exists(dotenv_path):
        return {}

    with open(dotenv_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    decrypted = {}
    needs_rewrite = False

    sensitive_upper = {v.upper() for v in sensitive_env_vars}

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # 匹配: [export ]KEY=value
        m = re.match(
            r'^(?:\s*export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$',
            stripped, re.IGNORECASE
        )
        if not m:
            continue

        env_key = m.group(1).upper()
        env_value_raw = m.group(2).strip()

        if env_key not in sensitive_upper:
            continue

        # 取出引号内的实际值
        env_value = env_value_raw
        if len(env_value_raw) >= 2 \
                and env_value_raw[0] == env_value_raw[-1] \
                and env_value_raw[0] in ('"', "'"):
            env_value = env_value_raw[1:-1]

        if not env_value:
            decrypted[env_key] = ""
            continue

        if is_encrypted(env_value):
            decrypted[env_key] = decrypt_value(env_value)
        else:
            encrypted = encrypt_value(env_value)
            # 在行内替换原始值
            lines[i] = line.replace(env_value_raw, '"' + encrypted + '"', 1)
            decrypted[env_key] = env_value
            needs_rewrite = True

    if needs_rewrite:
        temp_path = dotenv_path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            os.replace(temp_path, dotenv_path)
            logger.info("已自动加密 .env 中的敏感值")
        except Exception as e:
            logger.error("写入加密后的 .env 失败: %s", e)
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return decrypted
