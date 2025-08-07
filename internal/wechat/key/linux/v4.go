package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	linux_glance "github.com/sjzar/chatlog/internal/wechat/key/linux/glance"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	MaxWorkers = 16
)

type V4Extractor struct {
	validator *decrypt.Validator
}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, error) {
	if proc.Status == model.StatusOffline {
		return "", errors.ErrWeChatOffline
	}

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
func (e *V4Extractor) findMemory(ctx context.Context, pid uint32, memoryChannel chan<- []byte) error {
	// Initialize a Glance instance to read process memory
	g := linux_glance.NewGlance(pid)

	// Read memory data
	memory, err := g.Read()
	if err != nil {
		return err
	}

	log.Debug().Msgf("Memory region for analysis, size: %d bytes", len(memory))

	select {
	case memoryChannel <- memory:
		log.Debug().Msgf("Memory sent for analysis")
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
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
					if key := e.validateKey(memory, ptrValue, index); key != "" {
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
func (e *V4Extractor) validateKey(memory []byte, ptrValue uint64, patternIndex int) string {
	// For Linux, since we can't directly read from pointer address like Windows,
	// we need to find the corresponding location in our memory block

	// First, try to calculate the relative offset from the pointer value
	// This assumes the memory block starts from some base address
	// and the pointer points to a location within this block

	// Strategy 1: Try direct conversion if ptrValue might be a relative offset
	if int(ptrValue) >= 0 && int(ptrValue)+32 <= len(memory) {
		keyData := memory[ptrValue : ptrValue+32]
		if e.validator.Validate(keyData) {
			return hex.EncodeToString(keyData)
		}
	}

	// Strategy 2: Use pattern-relative offsets as fallback
	// These offsets are based on typical memory layouts around the pattern
	keyOffsets := []int{32, 48, 64, -32, -48, -64, 80, 96}

	for _, offset := range keyOffsets {
		keyOffset := patternIndex + offset
		if keyOffset < 0 || keyOffset+32 > len(memory) {
			continue
		}

		keyData := memory[keyOffset : keyOffset+32]

		// Validate key against database header
		if e.validator.Validate(keyData) {
			return hex.EncodeToString(keyData)
		}
	}

	return ""
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
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
			if key := e.validateKey(memory, ptrValue, index); key != "" {
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
