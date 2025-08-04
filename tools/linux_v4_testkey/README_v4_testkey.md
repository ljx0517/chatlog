# Ubuntu版本 V4 TestKey 工具

这是从macOS版本移植到Ubuntu的V4版本微信数据库密钥提取工具。

## 主要修改

### 1. 加密库替换
- **macOS**: CommonCrypto框架 → **Ubuntu**: OpenSSL库
- PBKDF2-SHA512实现更改为OpenSSL的PKCS5_PBKDF2_HMAC
- HMAC-SHA512实现更改为OpenSSL的HMAC接口

### 2. 内存访问方式替换
- **macOS**: Mach API (task_for_pid, mach_vm_read) → **Ubuntu**: /proc文件系统 + ptrace
- 内存区域搜索从VM_MEMORY_MALLOC_NANO更改为堆区域搜索
- 使用process_vm_readv进行高效内存读取

### 3. 进程管理替换
- **macOS**: Mach端口管理 → **Ubuntu**: ptrace系统调用
- 添加了进程附加和分离的错误处理

## 依赖要求

### 系统依赖
```bash
# 安装编译工具
sudo apt-get install build-essential

# 安装OpenSSL开发库
sudo apt-get install libssl-dev
```

### 权限要求
- 需要root权限或CAP_SYS_PTRACE能力
- 目标进程需要可访问（非内核进程）

## 编译方法

### 方法1: 使用编译脚本
```bash
cd internal/wechat/decrypt/linux/
chmod +x build.sh
./build.sh
```

### 方法2: 手动编译
```bash
gcc v4_testkey.c -o v4_testkey -O3 -lcrypto
```

## 使用方法

```bash
# 基本用法（需要root权限）
sudo ./v4_testkey <微信进程PID> <数据库文件路径>

# 示例
sudo ./v4_testkey 12345 /path/to/wechat.db
```

## 核心算法一致性

V4版本testkey算法与Go代码完全一致：

1. **Salt提取**: 从数据库第一页前16字节提取salt
2. **密钥派生**: 使用PBKDF2-SHA512，迭代256000次生成加密密钥
3. **MAC Salt生成**: salt XOR 0x3A
4. **MAC密钥派生**: 使用加密密钥，迭代2次生成MAC密钥
5. **HMAC计算**: 计算数据的HMAC-SHA512
6. **验证**: 比较计算的HMAC与存储的HMAC

## 内存搜索策略

- 搜索模式: `{0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00}`
- 偏移量尝试: `{16, -80, 64, -16, 32, -32}`
- 目标区域: 可读写的堆内存区域
- 安全限制: 单个内存区域搜索限制100MB

## 调试选项

编译时定义DEBUG宏可启用调试输出：
```bash
gcc -DDEBUG v4_testkey.c -o v4_testkey -O3 -lcrypto
```

## 注意事项

1. **权限要求**: 必须以root用户运行或具有CAP_SYS_PTRACE能力
2. **目标进程**: 确保微信进程正在运行且可访问
3. **数据库文件**: 确保数据库文件路径正确且可读
4. **内存搜索**: 搜索可能需要一些时间，特别是对于大内存进程

## 错误排查

### 编译错误
- 确保安装了`libssl-dev`
- 检查gcc版本是否支持

### 运行时错误
- `Permission denied`: 需要root权限
- `Failed to attach`: 检查目标进程是否存在且可访问
- `Failed to open db file`: 检查数据库文件路径和权限

## 与原版差异

这个Ubuntu版本保持了与macOS原版的核心算法一致性，主要差异在于：
- 使用OpenSSL替代CommonCrypto
- 使用Linux标准的内存访问方法
- 优化了内存搜索效率和安全性

## 文件结构

```
internal/wechat/decrypt/linux/
├── v4_testkey.c          # 主程序文件
├── build.sh              # 编译脚本
├── test_build.sh         # 测试脚本
├── README_v4_testkey.md  # 详细说明文档
└── USAGE_EXAMPLE.md      # 使用示例
```

## 相关文件

- **原版参考**: `internal/wechat/decrypt/darwin/v4_testkey.c` - macOS版本
- **Go实现**: `internal/wechat/decrypt/linux/v4.go` - 相同算法的Go实现
- **密钥提取**: `internal/wechat/key/linux/v4.go` - Linux密钥提取器

## 后续计划

1. **V3版本支持**: 添加V3版本的fallback逻辑
2. **性能优化**: 进一步优化大内存搜索效率
3. **错误处理**: 增强错误诊断和恢复机制
4. **文档完善**: 添加更多使用场景和故障排除指南

## 贡献指南

如需改进此工具，请：
1. 保持与Go版本算法的一致性
2. 添加适当的错误处理和边界检查
3. 更新相关文档和测试用例
4. 遵循Linux系统编程最佳实践

---

**Author**: Jaxon  
**Created**: 2024-12-19  
**Platform**: Ubuntu/Linux  
**Language**: C (OpenSSL)