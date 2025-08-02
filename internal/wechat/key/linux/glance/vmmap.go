package linux_glance

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/internal/errors"
)

const (
	FilterRegionType = "[heap]" // Linux heap regions
	FilterSHRMOD     = "SM=PRV" // Keep for compatibility
	CommandProcMaps  = "/proc/%d/maps"
)

type MemRegion struct {
	RegionType   string
	Start        uint64
	End          uint64
	VSize        uint64 // Size in bytes
	RSDNT        uint64 // Resident memory size in bytes (new field)
	SHRMOD       string
	Permissions  string
	RegionDetail string
}

func GetVmmap(pid uint32) ([]MemRegion, error) {
	// Read /proc/pid/maps file instead of vmmap command
	mapsFile := fmt.Sprintf(CommandProcMaps, pid)
	content, err := os.ReadFile(mapsFile)
	if err != nil {
		return nil, errors.RunCmdFailed(err)
	}

	// Parse the output using the updated LoadVmmap function
	return LoadVmmap(string(content))
}

func LoadVmmap(output string) ([]MemRegion, error) {
	var regions []MemRegion

	scanner := bufio.NewScanner(strings.NewReader(output))

	// Parse /proc/pid/maps format
	// Format: address           perms offset  dev   inode   pathname
	// Example: 55f4c0a00000-55f4c0a02000 r--p 00000000 08:01 1048576 /usr/bin/cat
	re := regexp.MustCompile(`^([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+)\s+[0-9a-f]+\s+[0-9a-f]+:[0-9a-f]+\s+\d+\s*(.*)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 5 {
			// Parse start and end addresses
			start, err := strconv.ParseUint(matches[1], 16, 64)
			if err != nil {
				continue
			}
			end, err := strconv.ParseUint(matches[2], 16, 64)
			if err != nil {
				continue
			}

			permissions := matches[3]
			pathname := strings.TrimSpace(matches[4])

			// Only include writable memory regions
			if !strings.Contains(permissions, "w") {
				continue
			}

			// Calculate size
			vsize := end - start

			// Determine region type based on pathname
			regionType := "UNKNOWN"
			if pathname == "" {
				regionType = "[anonymous]"
			} else if strings.Contains(pathname, "[heap]") {
				regionType = "[heap]"
			} else if strings.Contains(pathname, "[stack]") {
				regionType = "[stack]"
			} else if strings.Contains(pathname, ".so") {
				regionType = "[library]"
			} else {
				regionType = "[mapped]"
			}

			region := MemRegion{
				RegionType:   regionType,
				Start:        start,
				End:          end,
				VSize:        vsize,
				RSDNT:        vsize, // For Linux, assume all virtual memory is resident
				Permissions:  permissions,
				SHRMOD:       "PRV", // Default for Linux
				RegionDetail: pathname,
			}

			regions = append(regions, region)
		}
	}

	return regions, nil
}

func MemRegionsFilter(regions []MemRegion) []MemRegion {
	var filteredRegions []MemRegion
	for _, region := range regions {
		if region.RegionType == FilterRegionType {
			filteredRegions = append(filteredRegions, region)
		}
	}
	return filteredRegions
}

// parseSize converts size strings like "5616K" or "128.0M" to bytes (uint64)
func parseSize(sizeStr string) uint64 {
	// Remove any whitespace
	sizeStr = strings.TrimSpace(sizeStr)

	// Define multipliers for different units
	multipliers := map[string]uint64{
		"B":  1,
		"K":  1024,
		"KB": 1024,
		"M":  1024 * 1024,
		"MB": 1024 * 1024,
		"G":  1024 * 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
	}

	// Regular expression to match numbers with optional decimal point and unit
	// This will match formats like: "5616K", "128.0M", "1.5G", etc.
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)([KMGB]+)?$`)
	matches := re.FindStringSubmatch(sizeStr)

	if len(matches) < 2 {
		return 0 // No match found
	}

	// Parse the numeric part (which may include a decimal point)
	numStr := matches[1]
	numVal, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}

	// Determine the multiplier based on the unit
	multiplier := uint64(1) // Default if no unit specified
	if len(matches) >= 3 && matches[2] != "" {
		unit := matches[2]
		if m, ok := multipliers[unit]; ok {
			multiplier = m
		}
	}

	// Calculate final size in bytes (rounding to nearest integer)
	return uint64(numVal*float64(multiplier) + 0.5)
}
