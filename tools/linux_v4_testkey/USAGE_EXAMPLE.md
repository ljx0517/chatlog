# Ubuntu V4 TestKey 使用示例

## 快速开始

### 1. 环境准备
```bash
# Ubuntu/Debian 环境安装依赖
sudo apt-get update
sudo apt-get install build-essential libssl-dev

# 验证环境
gcc --version
pkg-config --exists libssl && echo "OpenSSL ready" || echo "OpenSSL missing"
```

### 2. 编译程序
```bash
# 方法1: 使用提供的脚本（推荐）
chmod +x build.sh
./build.sh

# 方法2: 手动编译
gcc v4_testkey.c -o v4_testkey -O3 -lcrypto
```

### 3. 使用示例

#### 基本使用
```bash
# 需要 root 权限或 CAP_SYS_PTRACE 能力
sudo ./v4_testkey <微信进程PID> <数据库文件路径>

# 示例
sudo ./v4_testkey 12345 /home/user/.local/share/wechat/msg.db
```

#### 查找微信进程
```bash
# 查找微信相关进程
ps aux | grep -i wechat
pgrep -f wechat

# 或者使用 top/htop 查看进程列表
top | grep wechat
```

#### 输出示例
```bash
$ sudo ./v4_testkey 12345 /path/to/wechat.db
WeChat V4 TestKey Tool - Ubuntu Version
Searching for V4 encryption key in process 12345...
Key validated with V4 algorithm
Found key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

## 调试模式

编译时启用调试输出：
```bash
gcc -DDEBUG v4_testkey.c -o v4_testkey_debug -O3 -lcrypto
sudo ./v4_testkey_debug 12345 /path/to/wechat.db
```

调试输出会显示：
- Reserve 大小计算
- 数据结束位置
- 计算的 HMAC 值
- 存储的 HMAC 值

## 权限设置

### 方法1: 使用 root 权限（推荐）
```bash
sudo ./v4_testkey <pid> <dbfile>
```

### 方法2: 设置 CAP_SYS_PTRACE 能力
```bash
# 为程序设置能力（避免每次使用 sudo）
sudo setcap cap_sys_ptrace=eip ./v4_testkey

# 现在可以非 root 用户运行
./v4_testkey <pid> <dbfile>
```

## 常见问题

### 编译错误
```bash
# 问题: fatal error: 'openssl/evp.h' file not found
# 解决: 安装 OpenSSL 开发库
sudo apt-get install libssl-dev

# 问题: gcc: command not found
# 解决: 安装编译工具
sudo apt-get install build-essential
```

### 运行时错误

#### 权限错误
```bash
# 错误: Failed to attach to process: Operation not permitted
# 解决: 使用 root 权限或设置 CAP_SYS_PTRACE
sudo ./v4_testkey <pid> <dbfile>
```

#### 进程不存在
```bash
# 错误: Failed to attach to process: No such process
# 解决: 检查进程是否存在
ps -p <pid>
```

#### 数据库文件错误
```bash
# 错误: Failed to open db file
# 解决: 检查文件路径和权限
ls -la /path/to/wechat.db
```

## 安全注意事项

1. **权限要求**: 程序需要较高权限来读取其他进程内存
2. **目标进程**: 确保目标进程是合法的微信进程
3. **数据安全**: 提取的密钥应安全存储，避免泄露
4. **法律合规**: 仅用于合法的数据恢复目的

## 性能优化

- 程序使用内存映射优化大内存区域搜索
- 单个内存区域搜索限制为 100MB
- 优先搜索堆内存区域以提高效率

## 与原版的兼容性

此 Ubuntu 版本与 macOS 原版在算法上完全一致：
- 相同的 V4 解密算法
- 相同的密钥搜索模式
- 相同的 PBKDF2-SHA512 参数
- 相同的 HMAC-SHA512 验证逻辑