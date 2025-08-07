package util

import (
	"os"
	"regexp"
	"strings"
)

type LLMConfig struct {
	Key     string `json:"llm_key"`  // API密钥
	Api     string `json:"lm_api"`   // API接口地址
	Model   string `json:"lm_model"` // 模型名称
	Prompts string `json:"prompts"`  // 模型名称
	Talkers string `json:"talkers"`  // 对话者/群组信息
	Cron    string `json:"cron"`     // 对话者/群组信息
}

type LLMConfigs []LLMConfig

var invalidCharsRegex = regexp.MustCompile(`[\\/:\*\?"<>\|]`)

func FormatValidFilename(name string, maxLen int) string {
	// 1. 替换非法字符为下划线
	validName := invalidCharsRegex.ReplaceAllString(name, "_")

	// 2. 处理首尾空格（避免空格导致的混淆）
	validName = strings.TrimSpace(validName)

	// 3. 处理空字符串（若替换后为空，默认用"unknown"）
	if validName == "" {
		validName = "unknown"
	}

	// 4. 截断过长的文件名
	if len(validName) > maxLen {
		validName = validName[:maxLen]
		// 避免截断后以点结尾（部分系统不允许）
		validName = strings.TrimSuffix(validName, ".")
	}

	// 5. 避免文件名以点结尾
	if strings.HasSuffix(validName, ".") {
		validName += "_"
	}

	return validName
}
func IsFile(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return !fileInfo.IsDir(), nil
}
