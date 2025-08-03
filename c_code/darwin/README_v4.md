# macOS V4 解密密钥提取工具

## 文件说明

### v4_testkey.c
真正的 V4 版本实现，与 Go 代码 `v4.go` 逻辑完全一致。

### v4poc.c  
原有文件，实际上是 V3 版本的实现（错误命名）。

## 编译方法

```bash
# 编译 V4 版本
clang v4_testkey.c -o v4_testkey -O3 -flto

# 编译调试版本（包含调试输出）
clang -DDEBUG v4_testkey.c -o v4_testkey_debug -O3 -flto
```

## 使用方法

```bash
# 提取密钥
./v4_testkey <微信进程PID> <数据库文件路径>

# 示例
./v4_testkey 12345 /path/to/wechat.db
```

## 技术差异对比

| 参数 | V3版本 (v4poc.c) | V4版本 (v4_testkey.c) |
|------|------------------|----------------------|
| 页面大小 | 1024字节 | 4096字节 |
| HMAC算法 | SHA1 | SHA512 |
| HMAC大小 | 20字节 | 64字节 |
| 密钥派生迭代次数 | 2次 | 256000次 |
| MAC密钥派生迭代次数 | 2次 | 2次 |

## 验证逻辑流程

1. 从数据库第一页提取 salt（前16字节）
2. 使用 PBKDF2-SHA512 派生加密密钥（256000次迭代）
3. 生成 MAC salt（原 salt XOR 0x3A）
4. 使用加密密钥派生 MAC 密钥（2次迭代）
5. 计算数据区域的 HMAC-SHA512
6. 与存储的 HMAC 比较验证

## 调试功能

编译时添加 `-DDEBUG` 可启用调试输出，显示：
- Reserve 大小计算
- 数据结束位置
- 计算的 HMAC 值
- 存储的 HMAC 值

这些信息有助于排查密钥验证失败的问题。