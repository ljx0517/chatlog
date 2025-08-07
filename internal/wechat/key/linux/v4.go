package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	linux_glance "github.com/sjzar/chatlog/internal/wechat/key/linux/glance"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	MaxWorkers        = 16
	MinRegionSize     = 1 * 1024 * 1024 // 1MB - 过滤小内存区域
	ChannelBuffer     = 200             // 优化channel缓冲区大小
	BatchValidateSize = 8               // 批量验证密钥数量
	MaxRetryAttempts  = 3               // 内存读取重试次数
)

type V4Extractor struct {
	validator    *decrypt.Validator
	currentPID   uint32       // 保存当前处理的PID，用于worker中的指针解引用
	memFile      *os.File     // /proc/pid/mem文件句柄，复用避免重复打开
	memFileMutex sync.RWMutex // 保护memFile的并发访问
}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, error) {
	if proc.Status == model.StatusOffline {
		return "", errors.ErrWeChatOffline
	}

	// 设置当前PID并初始化内存文件句柄
	e.currentPID = uint32(proc.PID)
	if err := e.initMemoryFile(); err != nil {
		return "", fmt.Errorf("failed to initialize memory file: %w", err)
	}
	defer e.closeMemoryFile()

	// Create context to control all goroutines
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for memory data and results - 优化缓冲区大小
	memoryChannel := make(chan []byte, ChannelBuffer)
	resultChannel := make(chan string, 1)

	// Determine number of worker goroutines
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers
	}
	log.Debug().Msgf("Starting %d workers for V4 key search", workerCount)

	// Start consumer goroutines
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			e.worker(searchCtx, memoryChannel, resultChannel)
		}()
	}

	// Start producer goroutine
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // Close channel when producer is done
		err := e.findMemory(searchCtx, uint32(proc.PID), memoryChannel)
		if err != nil {
			log.Err(err).Msg("Failed to find memory regions")
		}
	}()

	// Wait for producer and consumers to complete
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	// Wait for result
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result, ok := <-resultChannel:
		if ok && result != "" {
			return result, nil
		}
	}

	return "", errors.ErrNoValidKey
}

// initMemoryFile 初始化/proc/pid/mem文件句柄用于直接内存访问
func (e *V4Extractor) initMemoryFile() error {
	e.memFileMutex.Lock()
	defer e.memFileMutex.Unlock()

	if e.memFile != nil {
		return nil // 已经初始化
	}

	memPath := fmt.Sprintf("/proc/%d/mem", e.currentPID)
	file, err := os.OpenFile(memPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", memPath, err)
	}

	e.memFile = file
	log.Debug().Msgf("Successfully opened memory file for PID %d", e.currentPID)
	return nil
}

// closeMemoryFile 关闭内存文件句柄
func (e *V4Extractor) closeMemoryFile() {
	e.memFileMutex.Lock()
	defer e.memFileMutex.Unlock()

	if e.memFile != nil {
		e.memFile.Close()
		e.memFile = nil
		log.Debug().Msgf("Closed memory file for PID %d", e.currentPID)
	}
}

// findMemory searches for writable memory regions for V4 version
// 移植Windows V4的内存扫描策略：扫描多个内存区域而不是只读heap
func (e *V4Extractor) findMemory(ctx context.Context, pid uint32, memoryChannel chan<- []byte) error {
	// 获取所有内存区域信息
	regions, err := linux_glance.GetVmmap(pid)
	if err != nil {
		return err
	}

	// 应用Windows V4的过滤策略：扩展内存区域选择
	filteredRegions := e.filterMemoryRegions(regions)
	if len(filteredRegions) == 0 {
		return errors.ErrNoMemoryRegionsFound
	}

	log.Debug().Msgf("Found %d suitable memory regions for V4 key search", len(filteredRegions))

	// 逐个处理每个内存区域
	for i, region := range filteredRegions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Debug().Msgf("Processing region %d/%d: %s, size: %d MB",
			i+1, len(filteredRegions), region.RegionType, region.VSize/(1024*1024))

		// 读取内存区域数据
		memory, err := e.readMemoryRegion(pid, region)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to read memory region %s", region.RegionType)
			continue
		}

		select {
		case memoryChannel <- memory:
			log.Debug().Msgf("Memory region sent for analysis: %s, size: %d bytes",
				region.RegionType, len(memory))
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// filterMemoryRegions applies Windows V4 filtering strategy
// 扩展内存区域选择策略，不只是heap
func (e *V4Extractor) filterMemoryRegions(regions []linux_glance.MemRegion) []linux_glance.MemRegion {
	var filtered []linux_glance.MemRegion

	for _, region := range regions {
		// 应用Windows V4的过滤条件：
		// 1. 大小过滤：>= 1MB (学习Windows策略)
		if region.VSize < MinRegionSize {
			continue
		}

		// 2. 类型过滤：扩展到更多可写区域类型
		switch region.RegionType {
		case "[heap]": // 原有的heap区域
			filtered = append(filtered, region)
		case "[anonymous]": // 匿名内存映射
			filtered = append(filtered, region)
		case "[mapped]": // 映射文件（如果可写）
			if strings.Contains(region.Permissions, "w") {
				filtered = append(filtered, region)
			}
		}
	}

	log.Debug().Msgf("Filtered %d/%d memory regions using Windows V4 strategy",
		len(filtered), len(regions))
	return filtered
}

// readMemoryRegion reads a specific memory region using gdb
func (e *V4Extractor) readMemoryRegion(pid uint32, region linux_glance.MemRegion) ([]byte, error) {
	// 为单个内存区域创建Glance实例
	g := linux_glance.NewGlance(pid)

	// 设置特定的内存区域
	g.MemRegions = []linux_glance.MemRegion{region}

	return g.Read()
}

// readMemoryAtAddress 直接从/proc/pid/mem读取指定地址的内存
// 高效替代gdb方案，无需外部工具依赖
func (e *V4Extractor) readMemoryAtAddress(pid uint32, address uint64, size int) ([]byte, error) {
	e.memFileMutex.RLock()
	defer e.memFileMutex.RUnlock()

	if e.memFile == nil {
		return nil, fmt.Errorf("memory file not initialized for PID %d", pid)
	}

	// 重试机制处理临时读取失败
	var lastErr error
	for attempt := 0; attempt < MaxRetryAttempts; attempt++ {
		data := make([]byte, size)
		n, err := e.memFile.ReadAt(data, int64(address))

		if err == nil && n == size {
			log.Debug().Msgf("Successfully read %d bytes from address 0x%x (attempt %d)",
				size, address, attempt+1)
			return data, nil
		}

		lastErr = err
		if attempt < MaxRetryAttempts-1 {
			log.Debug().Err(err).Msgf("Read attempt %d failed, retrying...", attempt+1)
		}
	}

	return nil, fmt.Errorf("failed to read memory at 0x%x after %d attempts: %w",
		address, MaxRetryAttempts, lastErr)
}

// batchReadMemory 批量读取多个内存地址，减少系统调用开销
func (e *V4Extractor) batchReadMemory(candidates []uint64, keySize int) map[uint64][]byte {
	results := make(map[uint64][]byte)

	e.memFileMutex.RLock()
	defer e.memFileMutex.RUnlock()

	if e.memFile == nil {
		log.Warn().Msg("Memory file not initialized, skipping batch read")
		return results
	}

	for _, addr := range candidates {
		if data, err := e.readMemoryAtAddressUnsafe(addr, keySize); err == nil {
			results[addr] = data
		} else {
			log.Debug().Err(err).Msgf("Failed to read memory at 0x%x", addr)
		}
	}

	log.Debug().Msgf("Batch read completed: %d/%d successful", len(results), len(candidates))
	return results
}

// readMemoryAtAddressUnsafe 内部使用的无锁版本，用于批量操作
func (e *V4Extractor) readMemoryAtAddressUnsafe(address uint64, size int) ([]byte, error) {
	data := make([]byte, size)
	n, err := e.memFile.ReadAt(data, int64(address))
	if err != nil || n != size {
		return nil, fmt.Errorf("read failed at 0x%x: %w", address, err)
	}
	return data, nil
}

// worker processes memory regions to find V4 version key
func (e *V4Extractor) worker(ctx context.Context, memoryChannel <-chan []byte, resultChannel chan<- string) {
	// Define search pattern for V4
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ptrSize := 8
	littleEndianFunc := binary.LittleEndian.Uint64

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				return
			}

			// 收集所有候选指针地址，批量处理提升效率
			candidates := e.findCandidatePointers(memory, keyPattern, ptrSize, littleEndianFunc)
			if len(candidates) == 0 {
				continue
			}

			log.Debug().Msgf("Found %d candidate pointers for validation", len(candidates))

			// 批量验证候选指针
			if key := e.batchValidateKeys(candidates); key != "" {
				select {
				case resultChannel <- key:
					log.Debug().Msg("Valid key found: " + key)
					return
				default:
				}
			}
		}
	}
}

// findCandidatePointers 在内存中查找所有候选指针地址
func (e *V4Extractor) findCandidatePointers(memory []byte, keyPattern []byte, ptrSize int,
	littleEndianFunc func([]byte) uint64) []uint64 {
	var candidates []uint64
	index := len(memory)

	for {
		// Find pattern from end to beginning
		index = bytes.LastIndex(memory[:index], keyPattern)
		if index == -1 || index-ptrSize < 0 {
			break
		}

		// Extract and validate pointer value
		ptrValue := littleEndianFunc(memory[index-ptrSize : index])
		if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
			candidates = append(candidates, ptrValue)

			// 限制批量大小，避免内存占用过大
			if len(candidates) >= BatchValidateSize {
				break
			}
		}
		index -= 1
	}

	return candidates
}

// validateKey validates a single key candidate (保留单个验证用于兼容性)
func (e *V4Extractor) validateKey(pid uint32, ptrValue uint64) string {
	keyData, err := e.readMemoryAtAddress(pid, ptrValue, 32)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to read memory at address 0x%x", ptrValue)
		return ""
	}

	if e.validator.Validate(keyData) {
		return hex.EncodeToString(keyData)
	}

	return ""
}

// batchValidateKeys 批量验证候选密钥，提升验证效率
func (e *V4Extractor) batchValidateKeys(candidates []uint64) string {
	if len(candidates) == 0 {
		return ""
	}

	// 批量读取所有候选地址的数据
	keyDataMap := e.batchReadMemory(candidates, 32)
	if len(keyDataMap) == 0 {
		log.Debug().Msg("No valid memory reads from candidates")
		return ""
	}

	// 验证每个读取到的密钥数据
	for addr, keyData := range keyDataMap {
		if e.validator.Validate(keyData) {
			key := hex.EncodeToString(keyData)
			log.Debug().Msgf("Valid key found at address 0x%x: %s", addr, key)
			return key
		}
	}

	log.Debug().Msgf("No valid keys found in %d candidates", len(candidates))
	return ""
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// 注意：SearchKey需要预先设置currentPID才能正常工作
	if e.currentPID == 0 {
		log.Warn().Msg("SearchKey called without setting currentPID")
		return "", false
	}

	// Define search pattern for V4
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ptrSize := 8
	littleEndianFunc := binary.LittleEndian.Uint64

	// 使用批量处理提升效率
	candidates := e.findCandidatePointers(memory, keyPattern, ptrSize, littleEndianFunc)
	if len(candidates) == 0 {
		return "", false
	}

	// 批量验证，找到第一个有效密钥即返回
	if key := e.batchValidateKeys(candidates); key != "" {
		return key, true
	}

	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}
