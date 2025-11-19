import argparse
import hmac
import hashlib
import os
import math
import base64
import secrets
import string
from urllib.parse import urlparse

# --- 密码生成器核心配置 ---

# 推荐的字符集，包含大小写字母、数字和常用特殊符号
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.?~`"
CHARSET_LEN = len(CHARSET)  # 字符集长度
PASSWORD_LENGTH = 16        # 期望的密码长度

# --- 新增：生成随机主密钥的函数 ---

def generate_master_key(length: int = 32) -> str:
    """
    生成一个指定字节长度的、密码学安全的随机主密钥，并以 URL-safe base64 字符串返回。

    :param length: 原始字节长度（例如 32 表示 32 字节），默认 32
    :return: base64 编码形式的随机主密钥字符串
    """

    # 使用 secrets.token_bytes 生成高熵原始字节，然后以 URL-safe base64 表示为字符串
    if length <= 0:
        raise ValueError("密钥长度必须是正整数")

    raw = secrets.token_bytes(length)
    # 使用 URL safe base64 编码并返回字符串形式
    return base64.urlsafe_b64encode(raw).decode('ascii')


def normalize_url(url: str, include_path: bool = False, include_query: bool = False) -> str:
    """
    标准化 URL，默认只返回主机名（去掉 scheme, www, 端口），可选包含路径和查询参数。
    :param url: 原始 URL 或域名
    :param include_path: 是否包含路径
    :param include_query: 是否包含查询参数
    :return: 标准化后的字符串
    """
    if not url:
        return ''

    # 如果缺少 scheme，添加 https:// 以便 urlparse 正常解析 netloc
    if not url.startswith(('http://', 'https://')):
        url_to_parse = f'https://{url}'
    else:
        url_to_parse = url

    parsed = urlparse(url_to_parse)
    hostname = (parsed.hostname or '').lower()
    # 删除开头的 www.
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    normalized = hostname
    if include_path and parsed.path:
        # 去掉末尾斜杠
        normalized += parsed.path.rstrip('/')
    if include_query and parsed.query:
        normalized += '?' + parsed.query

    return normalized

# --- 密码生成器核心函数 ---

def generate_password(master_key: str, url: str, length: int = PASSWORD_LENGTH, include_path: bool = False, include_query: bool = False) -> str:
    """
    根据主密钥和网址生成一个确定性密码。默认长度为 16。

    :param master_key: 你的私人主密钥 (str)
    :param url: 网站的网址或域名 (str)
    :param length: 期望密码长度（默认 16）
    :param include_path: 密钥是否应包含 URL 的路径部分（默认为 False）
    :param include_query: 密钥是否应包含 URL 的查询字符串（默认为 False）
    :return: 生成的密码 (str)
    """
    # 1. 输入处理与标准化（默认只使用主机名）
    salt = "MySuperSecretPasswordGeneratorSalt2024"
    normalized_url = normalize_url(url, include_path=include_path, include_query=include_query)
    message = f"{salt}:{normalized_url}:{salt}".encode('utf-8')
    # 如果 master_key 是通过 generate_master_key 生成的 base64 字符串，优先将其解码为原始字节
    try:
        # base64 urlsafe 通常缺少 padding，补齐
        padding = '=' * (-len(master_key) % 4)
        key = base64.urlsafe_b64decode(master_key + padding)
    except Exception:
        # 回退到 utf-8 编码
        key = master_key.encode('utf-8')

    # 2. 计算 HMAC-SHA256 哈希值，按需追加更多 HMAC 输出以满足所需的随机位数
    pool = hmac.new(key, message, hashlib.sha256).digest()
    # 计算所需字节数（基于每字符熵）
    bits_per_char = math.log2(CHARSET_LEN)
    bits_needed = bits_per_char * length
    bytes_needed = math.ceil(bits_needed / 8)
    counter = 1
    # 如果初始哈希不足以生成足够的字节，继续扩展哈希材料（消息 + counter）
    while len(pool) < bytes_needed:
        pool += hmac.new(key, message + counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        counter += 1

    num = int.from_bytes(pool, 'big')
    password_chars = []
    for _ in range(length):
        num, rem = divmod(num, CHARSET_LEN)
        password_chars.append(CHARSET[rem])

    # 保证包含至少一个大写、一个小写、一个数字和一个特殊字符（确定性的选择）
    categories = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        ''.join(ch for ch in CHARSET if ch not in string.ascii_letters + string.digits)
    ]

    if length < len(categories):
        raise ValueError(f"密码长度必须至少为 {len(categories)}，以包含所有必需的字符类别")

    used_positions = set()
    for cat in categories:
        # 选择一个唯一的替换位置
        num, pos = divmod(num, length)
        while pos in used_positions:
            num, pos = divmod(num, length)
        used_positions.add(pos)

        # 在该类中选择一个字符
        num, idx = divmod(num, len(cat))
        password_chars[pos] = cat[idx]

    return ''.join(password_chars)

# --- 使用示例 ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="基于主密钥和网址的确定性密码生成器")
    parser.add_argument('-k', '--master-key', help='使用此主密钥 (字符串)')
    parser.add_argument('-f', '--master-key-file', help='从此文件读取主密钥')
    parser.add_argument('--generate', action='store_true', help='如果未提供主密钥，则生成一个新主密钥（默认情况下将其保存到文件，而不是打印）')
    parser.add_argument('--save-master-key', help='生成新密钥时，保存到此文件（默认：master_key.txt）')
    parser.add_argument('--print-master-key', action='store_true', help='打印生成的或提供的主密钥（不安全，仅在用户同意时）')
    parser.add_argument('-u', '--url', nargs='+', required=True, help='一个或多个要为其生成密码的 URL')
    parser.add_argument('-l', '--length', type=int, default=PASSWORD_LENGTH, help='所需的密码长度')
    parser.add_argument('--include-path', action='store_true', help='在 URL 规范化中包含路径')
    parser.add_argument('--include-query', action='store_true', help='在 URL 规范化中包含查询字符串')

    args = parser.parse_args()

    # 获取主密钥：优先命令行 > 文件 > 环境变量 > 生成
    master_key = None
    if args.master_key:
        master_key = args.master_key
    elif args.master_key_file:
        if os.path.exists(args.master_key_file):
            with open(args.master_key_file, 'r', encoding='utf-8') as f:
                master_key = f.read().strip()
        else:
            parser.error(f"主密钥文件未找到: {args.master_key_file}")
    elif os.environ.get('MASTER_KEY'):
        master_key = os.environ.get('MASTER_KEY')
    elif args.generate:
        master_key = generate_master_key(32)
        save_path = args.save_master_key or 'master_key.txt'
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(master_key)
        except Exception as e:
            parser.error(f"无法将生成的主密钥保存到 {save_path}: {e}")
    else:
        parser.error('请使用 --master-key、--master-key-file、MASTER_KEY 环境变量提供主密钥，或使用 --generate 生成新密钥')

    if args.print_master_key:
        # 提示用户敏感性风险
        print('\n【注意】主密钥 (你已请求显示):', master_key)

    # 生成密码
    for site in args.url:
        normalized = normalize_url(site, include_path=args.include_path, include_query=args.include_query)
        if not normalized:
            print(f"跳过无效 URL: {site}")
            continue
        # 确保 master_key 为字符串（静态检查的友好处理）
        master_key = str(master_key)
        pwd = generate_password(master_key, site, length=args.length, include_path=args.include_path, include_query=args.include_query)
        print(f"网站: {site}\n标准化: {normalized}\n密码: {pwd}\n")