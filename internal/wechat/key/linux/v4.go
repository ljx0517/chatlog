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
	MaxWorkers        = 8
	MinChunkSize      = 1 * 1024 * 1024 // 1MB
	ChunkOverlapBytes = 1024            // Greater than all offsets
	ChunkMultiplier   = 2               // Number of chunks = MaxWorkers * ChunkMultiplier
)

// V4 key search pattern based on Windows implementation
var V4KeyPattern = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

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

	// Check if SIP is disabled, as it's required for memory reading on macOS
	//if !glance.IsSIPDisabled() {
	//	return "", errors.ErrSIPEnabled
	//}

	if e.validator == nil {
		return "", errors.ErrValidatorNotSet
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
			log.Err(err).Msg("Failed to read memory")
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

// findMemory searches for memory regions using Glance
func (e *V4Extractor) findMemory(ctx context.Context, pid uint32, memoryChannel chan<- []byte) error {
	// Initialize a Glance instance to read process memory
	g := linux_glance.NewGlance(pid)

	// Read memory data
	memory, err := g.Read()
	if err != nil {
		return err
	}

	totalSize := len(memory)
	log.Debug().Msgf("Read memory region, size: %d bytes", totalSize)

	// If memory is small enough, process it as a single chunk
	if totalSize <= MinChunkSize {
		select {
		case memoryChannel <- memory:
			log.Debug().Msg("Memory sent as a single chunk for analysis")
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	chunkCount := MaxWorkers * ChunkMultiplier

	// Calculate chunk size based on fixed chunk count
	chunkSize := totalSize / chunkCount
	if chunkSize < MinChunkSize {
		// Reduce number of chunks if each would be too small
		chunkCount = totalSize / MinChunkSize
		if chunkCount == 0 {
			chunkCount = 1
		}
		chunkSize = totalSize / chunkCount
	}

	// Process memory in chunks from end to beginning
	for i := chunkCount - 1; i >= 0; i-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Calculate start and end positions for this chunk
			start := i * chunkSize
			end := (i + 1) * chunkSize

			// Ensure the last chunk includes all remaining memory
			if i == chunkCount-1 {
				end = totalSize
			}

			// Add overlap area to catch patterns at chunk boundaries
			if i > 0 {
				start -= ChunkOverlapBytes
				if start < 0 {
					start = 0
				}
			}

			chunk := memory[start:end]

			log.Debug().
				Int("chunk_index", i+1).
				Int("total_chunks", chunkCount).
				Int("chunk_size", len(chunk)).
				Int("start_offset", start).
				Int("end_offset", end).
				Msg("Processing memory chunk")

			select {
			case memoryChannel <- chunk:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// worker processes memory regions to find V4 version key
func (e *V4Extractor) worker(ctx context.Context, memoryChannel <-chan []byte, resultChannel chan<- string) {
	// Define search parameters for V4 (based on Windows implementation)
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
				index = bytes.LastIndex(memory[:index], V4KeyPattern)
				if index == -1 || index-ptrSize < 0 {
					break
				}

				// Extract and validate pointer value
				ptrValue := littleEndianFunc(memory[index-ptrSize : index])
				if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
					// For Linux, we can't directly read from pointer address like Windows
					// Instead, we validate the key data at the pattern location
					if key := e.validateKeyAtPattern(memory, index); key != "" {
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

// validateKeyAtPattern validates a key candidate at the pattern location
func (e *V4Extractor) validateKeyAtPattern(memory []byte, patternIndex int) string {
	// Try different offsets to find the key relative to the pattern
	// These offsets are based on typical memory layouts around the pattern
	keyOffsets := []int{32, 48, 64, -32, -48, -64, 80, 96}

	for _, offset := range keyOffsets {
		keyOffset := patternIndex + offset
		if keyOffset < 0 || keyOffset+32 > len(memory) {
			continue
		}

		keyData := memory[keyOffset : keyOffset+32]

		// Validate key against database header
		if e.validator != nil && e.validator.Validate(keyData) {
			log.Debug().
				Int("pattern_index", patternIndex).
				Int("key_offset", offset).
				Str("key", hex.EncodeToString(keyData)).
				Msg("Valid key found at pattern location")
			return hex.EncodeToString(keyData)
		}
	}

	return ""
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// Use the same logic as worker function for consistency
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
		index = bytes.LastIndex(memory[:index], V4KeyPattern)
		if index == -1 || index-ptrSize < 0 {
			break
		}

		// Extract and validate pointer value
		ptrValue := littleEndianFunc(memory[index-ptrSize : index])
		if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
			if key := e.validateKeyAtPattern(memory, index); key != "" {
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
