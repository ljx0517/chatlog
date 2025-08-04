// Ubuntu版本的V4 testkey实现，与v4.go逻辑一致
// 编译命令: gcc v4_testkey_linux.c -o v4_testkey_linux -O3 -lcrypto
// 
// 依赖安装 (Ubuntu/Debian):
// sudo apt-get install build-essential libssl-dev
//
// 注意: 此代码专为Linux设计，使用OpenSSL和ptrace系统调用

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// Linux特有的头文件，只在Linux系统上包含
#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#endif

// V4版本常量 - 与Go代码中的常量保持一致
#define V4_PAGE_SIZE 4096
#define KEY_SIZE 32
#define SALT_SIZE 16
#define HMAC_SHA512_SIZE 64
#define IV_SIZE 16
#define AES_BLOCK_SIZE 16
#define V4_ITER_COUNT 256000

/**
 * PBKDF2-SHA512实现
 */
int pbkdf2_sha512(const unsigned char *password, int password_len,
                  const unsigned char *salt, int salt_len,
                  int iterations, unsigned char *key, int key_len) {
    return PKCS5_PBKDF2_HMAC((const char *)password, password_len,
                             salt, salt_len, iterations,
                             EVP_sha512(), key_len, key);
}

/**
 * V4版本的testkey函数 - 与Go代码中的V4Decryptor.Validate逻辑完全一致
 * @param page 数据库第一页内容
 * @param key 待验证的密钥
 * @return 密钥是否有效
 */
bool testkey_v4(const unsigned char *page, const unsigned char *key) {
    if (!page || !key) {
        return false;
    }

    // 1. 从第一页提取salt (前16字节)
    unsigned char salt[SALT_SIZE];
    memcpy(salt, page, SALT_SIZE);

    // 2. 派生加密密钥 - 使用PBKDF2-SHA512，迭代256000次
    unsigned char enc_key[KEY_SIZE];
    if (pbkdf2_sha512(key, KEY_SIZE, salt, SALT_SIZE, 
                      V4_ITER_COUNT, enc_key, KEY_SIZE) != 1) {
        return false;
    }

    // 3. 生成MAC salt - salt XOR 0x3A
    unsigned char mac_salt[SALT_SIZE];
    for (int i = 0; i < SALT_SIZE; i++) {
        mac_salt[i] = salt[i] ^ 0x3A;
    }

    // 4. 派生MAC密钥 - 使用enc_key作为输入，迭代2次
    unsigned char mac_key[KEY_SIZE];
    if (pbkdf2_sha512(enc_key, KEY_SIZE, mac_salt, SALT_SIZE,
                      2, mac_key, KEY_SIZE) != 1) {
        return false;
    }

    // 5. 计算reserve大小
    int reserve = IV_SIZE + HMAC_SHA512_SIZE;
    if (reserve % AES_BLOCK_SIZE != 0) {
        reserve = ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }

    // 6. 计算数据结束位置
    int data_end = V4_PAGE_SIZE - reserve + IV_SIZE;

    // 7. 计算HMAC-SHA512 - 使用简化的HMAC接口
    unsigned char calculated_hmac[HMAC_SHA512_SIZE];
    unsigned int hmac_len = HMAC_SHA512_SIZE;

    // 准备要计算HMAC的数据
    size_t data_len = (data_end - SALT_SIZE) + 4; // 数据长度 + 页码长度
    unsigned char *hmac_data = malloc(data_len);
    if (!hmac_data) {
        return false;
    }

    // 8. 拷贝数据 - 从salt后开始到数据结束位置
    memcpy(hmac_data, page + SALT_SIZE, data_end - SALT_SIZE);

    // 9. 添加页码 (第一页 = 1，小端序)
    unsigned char page_no[4] = {1, 0, 0, 0};  // 小端序的1
    memcpy(hmac_data + (data_end - SALT_SIZE), page_no, 4);

    // 10. 计算HMAC-SHA512
    unsigned char *result = HMAC(EVP_sha512(), mac_key, KEY_SIZE, 
                                hmac_data, data_len, calculated_hmac, &hmac_len);
    free(hmac_data);
    
    if (!result || hmac_len != HMAC_SHA512_SIZE) {
        return false;
    }

    // 11. 提取存储的HMAC并比较
    const unsigned char *stored_hmac = page + data_end;
    
    // 调试输出（可选）
//    #ifdef DEBUG
    printf("Reserve: %d, Data end: %d\n", reserve, data_end);
    printf("Calculated HMAC: ");
    for (int i = 0; i < HMAC_SHA512_SIZE; i++) {
        printf("%02x", calculated_hmac[i]);
    }
    printf("\n");
    printf("Stored HMAC: ");
    for (int i = 0; i < HMAC_SHA512_SIZE; i++) {
        printf("%02x", stored_hmac[i]);
    }
    printf("\n");
//    #endif

    // 12. 比较HMAC值
    return memcmp(calculated_hmac, stored_hmac, HMAC_SHA512_SIZE) == 0;
}

/**
 * 兼容的testkey函数，自动检测版本
 * @param page 数据库第一页内容
 * @param key 待验证的密钥
 * @return 密钥是否有效
 */
bool testkey(const unsigned char *page, const unsigned char *key) {
    // 先尝试V4版本
    if (testkey_v4(page, key)) {
        printf("Key validated with V4 algorithm\n");
        return true;
    }
    
    // 如果V4失败，可以在这里添加V3的fallback逻辑
    printf("Key validation failed with V4 algorithm\n");
    return false;
}

/**
 * 读取进程内存 - 仅在Linux上可用
 */
int read_process_memory(pid_t pid, unsigned long addr, void *buffer, size_t size) {
#ifdef __linux__
    struct iovec local[1];
    struct iovec remote[1];
    
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = size;
    
    ssize_t bytes_read = process_vm_readv(pid, local, 1, remote, 1, 0);
    return (bytes_read == (ssize_t)size) ? 0 : -1;
#else
    fprintf(stderr, "Error: Memory reading is only supported on Linux\n");
    return -1;
#endif
}

/**
 * 搜索进程内存中的密钥模式
 */
int search_memory_region(pid_t pid, unsigned long start, unsigned long end, 
                        const unsigned char *page, char *outkey) {
    unsigned char *buffer;
    size_t region_size = end - start;
    
    // 限制搜索区域大小，避免内存过大
    if (region_size > 100 * 1024 * 1024) { // 100MB限制
        return -1;
    }
    
    buffer = malloc(region_size);
    if (!buffer) {
        return -1;
    }
    
    if (read_process_memory(pid, start, buffer, region_size) != 0) {
        free(buffer);
        return -1;
    }
    
    // 密钥搜索模式
    unsigned char pattern[8] = {0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00};
    
    for (size_t i = 0; i <= region_size - sizeof(pattern); i++) {
        if (memcmp(buffer + i, pattern, sizeof(pattern)) == 0) {
         printf("11111111\n");
            // 尝试不同的偏移量
            int offsets[] = {16, -80, 64, -16, 32, -32};
            int num_offsets = sizeof(offsets) / sizeof(offsets[0]);
            
            for (int j = 0; j < num_offsets; j++) {
                long key_offset = (long)i + offsets[j];
                
                // 检查边界
                if (key_offset < 0 || key_offset + KEY_SIZE > (long)region_size) {
                    continue;
                }
                
                unsigned char *key = buffer + key_offset;
                
                // 测试密钥
                if (testkey_v4(page, key)) {
                    // 找到有效密钥，转换为十六进制字符串
                    for (int k = 0; k < KEY_SIZE; k++) {
                        sprintf(outkey + k * 2, "%02x", key[k]);
                    }
                    outkey[KEY_SIZE * 2] = '\0';
                    
                    free(buffer);
                    return 0;
                }
            }
        }
    }
    
    free(buffer);
    return -1;
}

/**
 * 从/proc/pid/maps读取内存映射信息并搜索密钥 - 仅在Linux上可用
 */
int dumpkey(pid_t pid, const char *filename, char *outkey) {
#ifndef __linux__
    fprintf(stderr, "Error: This function is only supported on Linux\n");
    return -1;
#else
    // 读取数据库第一页
    unsigned char page[V4_PAGE_SIZE];
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open db file: %s\n", filename);
        return -1;
    }
    
    size_t read_size = fread(page, 1, V4_PAGE_SIZE, fp);
    fclose(fp);
    
    if (read_size != V4_PAGE_SIZE) {
        fprintf(stderr, "Failed to read complete first page (read %zu bytes, expected %d)\n", 
                read_size, V4_PAGE_SIZE);
        return -1;
    }

    // 附加到目标进程
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Failed to attach to process %d: %s\n", pid, strerror(errno));
        return -1;
    }
    
    // 等待进程停止
    int status;
    waitpid(pid, &status, 0);
    
    // 读取内存映射信息
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        fprintf(stderr, "Failed to open %s: %s\n", maps_path, strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char permissions[5];
        fprintf(stderr, line);
        bool heap_start = false;
        if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) == 3) {
            if (  strstr(line, "[heap]")) {
            heap_start= true;
            continue;
            }
            if (heap_start && strstr(line, "[") ) {
            heap_start = false;
            break;
            }
             fprintf(stderr, "permissions %c %c", permissions[0] ,  permissions[1] );
            // 只搜索可读写的区域，主要是堆区域
            if (permissions[0] == 'r' && permissions[1] == 'w' ) {
                fprintf(stderr, "try %ld %ld", start, end);
                if (search_memory_region(pid, start, end, page, outkey) == 0) {
                    fclose(maps_file);
                    ptrace(PTRACE_DETACH, pid, NULL, NULL);
                    return 0;
                }
            }
        }
    }
    
    fclose(maps_file);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
#endif
}

int main(int argc, char *argv[]) {
    printf("WeChat V4 TestKey Tool - Ubuntu Version\n");
    
#ifndef __linux__
    fprintf(stderr, "Error: This tool is designed for Linux systems only\n");
    fprintf(stderr, "Current platform is not supported for memory operations\n");
    fprintf(stderr, "However, the testkey validation function can still be used\n");
#endif

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <dbfile>\n", argv[0]);
        fprintf(stderr, "Extract WeChat database encryption key from process memory (V4 - Linux)\n");
#ifdef __linux__
        fprintf(stderr, "Note: This program requires root privileges or CAP_SYS_PTRACE capability\n");
#endif
        return -1;
    }

    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return -1;
    }

    char key[KEY_SIZE * 2 + 1] = {0};
    printf("Searching for V4 encryption key in process %d...\n", pid);
    
    if (dumpkey(pid, argv[2], key) == 0) {
        printf("Found key: %s\n", key);
        return 0;
    } else {
        printf("Key not found\n");
        return -1;
    }
}