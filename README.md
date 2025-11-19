# Deterministic Password Generator

轻量级确定性密码生成器：基于主密钥 + 网站 URL 使用 HMAC-SHA256 生成可复现的密码，便于不保存每站密码的情况下管理密码。

## 关键特性

- 确定性生成：相同主密钥 + 相同标准化 URL 总是生成相同密码。
- URL 标准化：默认只使用主机名，可选包含路径与查询参数（`--include-path`, `--include-query`）。
- 强制字符类别：保证每个密码包含至少一个大写、一个小写、一个数字和一个特殊字符（以确定方式选取）。
- 基于大整数的 base-N 映射，避免 byte % CHARSET_LEN 导致的偏差。
- CLI：支持主密钥生成 / 读取 / 保存、密码长度设置与格式化选项。

## 快速开始

1. 克隆仓库并进入目录

```bash
git clone <repo-url>
cd Password-Generator
```

2. （可选）创建并激活虚拟环境

```bash
python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate
```

3. 安装测试依赖（脚本运行不依赖额外包，但运行测试需要 pytest）

```bash
pip install -r requirements.txt
```

## CLI 使用示例

- 生成一个新主密钥（以 base64 存储）并为两个站点生成密码；默认会把主密钥保存为 `master_key.txt`：
```bash
python main.py --generate --save-master-key master_key.txt --url https://github.com https://www.google.com
```
- 使用已有主密钥文件：
```bash
python main.py -f master_key.txt --url https://example.com
```
- 使用环境变量 `MASTER_KEY`：
```bash
# PowerShell 示例
$env:MASTER_KEY = "$(python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")"
python main.py --url https://example.com
```
- 指定密码长度、包含路径或查询参数：
```bash
python main.py -f master_key.txt --url 'https://example.com/path?x=1' --include-path --include-query -l 24
```
- 如果确实需要查看主密钥，请用 `--print-master-key`（此选项会在控制台打印主密钥，通常不推荐）：
```bash
python main.py -f master_key.txt --url https://example.com --print-master-key
```

## 安全注意事项

- 主密钥非常敏感，请勿提交到 Git 或其他公共仓库。
- 推荐把主密钥保存到受信任的密码管理器或 OS 安全存储，而不是明文保存到文件。
- 如果意外将 `master_key.txt` 提交到仓库中，应立即撤销历史提交（例如使用 `git filter-repo` 或 `BFG Repo Cleaner`），并更换主密钥。

## 实现细节（简要）

- `generate_master_key(length=32)`：使用 `secrets.token_bytes(32)` 生成高熵原始字节并以 URL-safe base64 字符串返回，便于展示与保存。
- `generate_password(master_key, url, length=16)`：
  - 标准化 URL（默认只取主机名），可选路径/查询；
  - 使用 `salt:normalized_url:salt` 通过 `hmac.new(key, message, hashlib.sha256)` 生成基本哈希池；
  - 需要更多随机位时继续以 `message + counter` 生成哈希以扩展池（避免不足以支持较长密码）；
  - 将哈希池解释为大整数并以 base-N（N=字符集大小）生成密码字符，减少偏置；
  - 使用哈希池的数值决定位置与字符，**确定性**插入满足 4 类字符的字符，确保每种字符类别至少出现一次；
  - 支持 `length` 参数（但若 `length < 4` 会抛错，因为无法安放 4 个必需类别）。

## 测试

- 运行测试：
```bash
python -m pytest
```

## 目录结构

- `main.py`：主程序
- `tests/`：pytest 测试集
- `.gitignore`：忽略定义（已包含诸多常见项，建议不要提交密钥等）
- `requirements.txt`：测试依赖（`pytest`）

## 后续功能

- 增加将主密钥保存到 OS 密钥链或加密本地存储的功能。
- 添加更可配置的策略（例如不把某些类别强制进密码，或改变字符集）。
- 添加导出与迁移支持（例如生成旧密码清单来逐步迁移网站密码）。