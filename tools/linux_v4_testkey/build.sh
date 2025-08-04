#!/bin/bash
# Ubuntu环境下编译v4_testkey的脚本

# 检查是否安装了必要的依赖
echo "Checking dependencies..."

# 检查gcc
if ! command -v gcc &> /dev/null; then
    echo "Error: gcc is not installed"
    echo "Please install with: sudo apt-get install build-essential"
    exit 1
fi

# 检查OpenSSL开发库
if ! pkg-config --exists libssl; then
    echo "Error: OpenSSL development libraries are not installed"
    echo "Please install with: sudo apt-get install libssl-dev"
    exit 1
fi

echo "Dependencies OK"

# 编译
echo "Compiling v4_testkey..."
gcc v4_testkey.c -o v4_testkey -O3 -lcrypto

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Binary created: v4_testkey"
    echo ""
    echo "Usage: sudo ./v4_testkey <pid> <dbfile>"
    echo "Note: Root privileges are required for memory access"
else
    echo "Compilation failed!"
    exit 1
fi