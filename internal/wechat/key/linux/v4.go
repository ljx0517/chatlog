package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	linux_glance "github.com/sjzar/chatlog/internal/wechat/key/linux/glance"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	MaxWorkers    = 16
	MinRegionSize = 1 * 1024 * 1024 // 1MB - 学习Windows策略，过滤小内存区域
)

type V4Extractor struct {
	validator  *decrypt.Validator
	currentPID uint32 // 保存当前处理的PID，用于worker中的指针解引用
}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, error) {
	if proc.Status == model.StatusOffline {
		return "", errors.ErrWeChatOffline
	}

	// 设置当前PID，用于worker中的指针解引用
	e.currentPID = uint32(proc.PID)

	// Create context to control all goroutines
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for memory data and results
	memoryChannel := make(chan []byte, 100)
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

// readMemoryAtAddress reads specific memory address using gdb
// 这是Windows ReadProcessMemory在Linux上的等效实现
func (e *V4Extractor) readMemoryAtAddress(pid uint32, address uint64, size int) ([]byte, error) {
	// 使用gdb直接从指定地址读取内存
	pipePath := filepath.Join(os.TempDir(), fmt.Sprintf("chatlog_key_pipe_%d_%x", pid, address))

	// 创建命名管道
	if err := exec.Command("mkfifo", pipePath).Run(); err != nil {
		return nil, errors.CreatePipeFileFailed(err)
	}
	defer os.Remove(pipePath)

	// 启动读取goroutine
	dataCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		file, err := os.OpenFile(pipePath, os.O_RDONLY, 0600)
		if err != nil {
			errCh <- errors.OpenPipeFileFailed(err)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			errCh <- errors.ReadPipeFileFailed(err)
			return
		}
		dataCh <- data
	}()

	// 执行gdb命令读取指定地址的内存
	endAddr := address + uint64(size)
	gdbCmd := fmt.Sprintf("gdb -p %d -batch -ex \"dump binary memory %s 0x%x 0x%x\" -ex \"quit\"",
		pid, pipePath, address, endAddr)

	cmd := exec.Command("bash", "-c", gdbCmd)
	if err := cmd.Start(); err != nil {
		return nil, errors.RunCmdFailed(err)
	}

	// 等待读取完成
	select {
	case data := <-dataCh:
		cmd.Wait() // 等待gdb进程结束
		return data, nil
	case err := <-errCh:
		cmd.Process.Kill()
		return nil, err
	case <-time.After(10 * time.Second): // 指定地址读取应该很快
		cmd.Process.Kill()
		return nil, errors.ErrReadMemoryTimeout
	}
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

			index := len(memory)
			for {
				select {
				case <-ctx.Done():
					return // Exit if context cancelled
				default:
				}

				// Find pattern from end to beginning
				index = bytes.LastIndex(memory[:index], keyPattern)
				if index == -1 || index-ptrSize < 0 {
					break
				}

				// Extract and validate pointer value
				ptrValue := littleEndianFunc(memory[index-ptrSize : index])
				if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
					// 使用Windows V4的验证策略：直接读取指针地址
					if key := e.validateKey(e.currentPID, ptrValue); key != "" {
						select {
						case resultChannel <- key:
							log.Debug().Msg("Valid key found: " + key)
							return
						default:
						}
					}
				}
				index -= 1 // Continue searching from previous position
			}
		}
	}
}

// validateKey validates a single key candidate
// 移植Windows V4的验证策略：通过gdb直接读取指针地址
func (e *V4Extractor) validateKey(pid uint32, ptrValue uint64) string {
	// 使用gdb直接读取指针指向的32字节数据
	// 这是Windows V4中ReadProcessMemory的Linux等效实现
	keyData, err := e.readMemoryAtAddress(pid, ptrValue, 32)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to read memory at address 0x%x", ptrValue)
		return ""
	}

	// 直接验证密钥，与Windows V4逻辑完全一致
	if e.validator.Validate(keyData) {
		return hex.EncodeToString(keyData)
	}

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
	index := len(memory)

	for {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}

		// Find pattern from end to beginning
		index = bytes.LastIndex(memory[:index], keyPattern)
		if index == -1 || index-ptrSize < 0 {
			break
		}

		// Extract and validate pointer value
		ptrValue := littleEndianFunc(memory[index-ptrSize : index])
		if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
			// 使用Windows V4的验证策略：直接读取指针地址
			if key := e.validateKey(e.currentPID, ptrValue); key != "" {
				return key, true
			}
		}
		index -= 1
	}

	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}
