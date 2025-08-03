// clang v4_testkey_darwin.c -o v4_testkey_darwin -O3 -flto
// 这是真正的V4版本testkey实现，与v4.go逻辑一致

#include <CommonCrypto/CommonCrypto.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// V4版本常量 - 与Go代码中的常量保持一致
#define V4_PAGE_SIZE 4096
#define KEY_SIZE 32
#define SALT_SIZE 16
#define HMAC_SHA512_SIZE 64
#define IV_SIZE 16
#define AES_BLOCK_SIZE 16
#define V4_ITER_COUNT 256000

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
    int result = CCKeyDerivationPBKDF(kCCPBKDF2, 
                                     (const char *)key, KEY_SIZE,
                                     salt, SALT_SIZE,
                                     kCCPRFHmacAlgSHA512,  // 使用SHA512
                                     V4_ITER_COUNT,        // 256000次迭代
                                     enc_key, KEY_SIZE);
    if (result != kCCSuccess) {
        return false;
    }

    // 3. 生成MAC salt - salt XOR 0x3A
    unsigned char mac_salt[SALT_SIZE];
    for (int i = 0; i < SALT_SIZE; i++) {
        mac_salt[i] = salt[i] ^ 0x3A;
    }

    // 4. 派生MAC密钥 - 使用enc_key作为输入，迭代2次
    unsigned char mac_key[KEY_SIZE];
    result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                 (const char *)enc_key, KEY_SIZE,
                                 mac_salt, SALT_SIZE,
                                 kCCPRFHmacAlgSHA512,  // 使用SHA512
                                 2,                    // 2次迭代
                                 mac_key, KEY_SIZE);
    if (result != kCCSuccess) {
        return false;
    }

    // 5. 计算reserve大小
    int reserve = IV_SIZE + HMAC_SHA512_SIZE;
    if (reserve % AES_BLOCK_SIZE != 0) {
        reserve = ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }

    // 6. 计算数据结束位置
    int data_end = V4_PAGE_SIZE - reserve + IV_SIZE;

    // 7. 初始化HMAC-SHA512上下文
    CCHmacContext hmac_context;
    CCHmacInit(&hmac_context, kCCHmacAlgSHA512, mac_key, KEY_SIZE);

    // 8. 更新HMAC - 从salt后开始到数据结束位置
    CCHmacUpdate(&hmac_context, page + SALT_SIZE, data_end - SALT_SIZE);

    // 9. 更新HMAC - 添加页码 (第一页 = 1，小端序)
    unsigned char page_no[4] = {1, 0, 0, 0};  // 小端序的1
    CCHmacUpdate(&hmac_context, page_no, 4);

    // 10. 计算最终HMAC
    unsigned char calculated_hmac[HMAC_SHA512_SIZE];
    CCHmacFinal(&hmac_context, calculated_hmac);

    // 11. 提取存储的HMAC并比较
    const unsigned char *stored_hmac = page + data_end;
    
    // 调试输出（可选）
    #ifdef DEBUG
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
    #endif

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

// 以下是完整的dumpkey函数实现
int dumpkey(pid_t pid, const char *filename, char *outkey) {
    mach_port_name_t target_task;
    kern_return_t kr;
    
    kr = task_for_pid(mach_task_self(), pid, &target_task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %s (%d)\n", mach_error_string(kr), kr);
        return -1;
    }

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

    // 搜索内存中的密钥
    mach_vm_address_t address = 0;
    mach_vm_size_t size;
    vm_region_extended_info_data_t info;
    mach_msg_type_number_t infoCnt = VM_REGION_EXTENDED_INFO_COUNT;
    mach_port_t object_name;
    
    // 密钥搜索模式
    unsigned char pattern[8] = {0x20, 0x66, 0x74, 0x73, 0x35, 0x28, 0x25, 0x00};

    while (1) {
        kr = mach_vm_region(target_task, &address, &size, VM_REGION_EXTENDED_INFO,
                           (vm_region_info_t)&info, &infoCnt, &object_name);
        if (kr != KERN_SUCCESS) {
            break;
        }

        // 检查内存区域是否可读写且为malloc nano区域
        if ((info.protection & VM_PROT_READ) && 
            (info.protection & VM_PROT_WRITE) &&
            (info.user_tag == VM_MEMORY_MALLOC_NANO)) {

            unsigned char *data = malloc(size);
            if (!data) {
                address += size;
                continue;
            }

            mach_vm_size_t outsize = 0;
            kr = mach_vm_read_overwrite(target_task, address, size,
                                       (mach_vm_address_t)data, &outsize);
            if (kr != KERN_SUCCESS) {
                free(data);
                address += size;
                continue;
            }

            // 搜索模式
            unsigned char *pos = data;
            unsigned char *end = pos + outsize;
            
            while ((pos = memmem(pos, end - pos, pattern, sizeof(pattern)))) {
                // 尝试不同的偏移量
                int offsets[] = {16, -80, 64, -16, 32, -32};
                int num_offsets = sizeof(offsets) / sizeof(offsets[0]);

                for (int i = 0; i < num_offsets; i++) {
                    unsigned char *key = pos + offsets[i];
                    
                    // 检查边界
                    if (key < data || key + KEY_SIZE > end) {
                        continue;
                    }

                    // 测试密钥
                    if (testkey_v4(page, key)) {
                        // 找到有效密钥，转换为十六进制字符串
                        for (int j = 0; j < KEY_SIZE; j++) {
                            sprintf(outkey + j * 2, "%02x", key[j]);
                        }
                        outkey[KEY_SIZE * 2] = '\0';
                        
                        free(data);
                        return 0;
                    }
                }
                pos++;
            }
            free(data);
        }
        address += size;
    }

    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <dbfile>\n", argv[0]);
        fprintf(stderr, "Extract WeChat database encryption key from process memory (V4)\n");
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