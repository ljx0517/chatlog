#!/bin/bash
# Ubuntu环境下的构建测试脚本

echo "=== Ubuntu V4 TestKey 构建测试 ==="
echo ""

# 检查操作系统
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "警告: 此代码专为Linux设计，当前系统: $OSTYPE"
    echo "如果在macOS上测试，请确保已安装OpenSSL:"
    echo "  brew install openssl"
    echo "  export PKG_CONFIG_PATH=\"/opt/homebrew/lib/pkgconfig\""
    echo ""
fi

# 检查依赖
echo "1. 检查编译器..."
if command -v gcc &> /dev/null; then
    echo "✓ gcc 已安装: $(gcc --version | head -n1)"
else
    echo "✗ gcc 未安装"
    exit 1
fi

echo ""
echo "2. 检查OpenSSL库..."
if pkg-config --exists libssl 2>/dev/null; then
    echo "✓ libssl 已安装: $(pkg-config --modversion libssl)"
elif [ -d "/opt/homebrew/lib" ] && ls /opt/homebrew/lib/libssl* &> /dev/null; then
    echo "✓ macOS Homebrew OpenSSL 已安装"
    export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
else
    echo "✗ OpenSSL开发库未安装"
    echo "Ubuntu/Debian: sudo apt-get install libssl-dev"
    echo "macOS: brew install openssl"
    exit 1
fi

echo ""
echo "3. 尝试编译..."

# 尝试编译
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS 编译
    gcc v4_testkey.c -o v4_testkey_test -O3 -I/opt/homebrew/include -L/opt/homebrew/lib -lcrypto
else
    # Linux 编译
    gcc v4_testkey_linux.c -o v4_testkey_linux -O3 -lcrypto
fi

if [ $? -eq 0 ]; then
    echo "✓ 编译成功!"
    echo "生成的可执行文件: v4_testkey_test"
    
    # 显示文件信息
    if [ -f "v4_testkey_test" ]; then
        echo ""
        echo "文件信息:"
        ls -la v4_testkey_test
        file v4_testkey_test
        
        echo ""
        echo "使用方法:"
        echo "  sudo ./v4_testkey_test <pid> <dbfile>"
        
        # 清理测试文件
#        rm -f v4_testkey_test
        echo ""
        echo "测试文件已清理"
    fi
else
    echo "✗ 编译失败!"
    exit 1
fi

echo ""
echo "=== 构建测试完成 ==="