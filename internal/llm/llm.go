package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type ChatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      ChatMessage `json:"message"`
		Delta        ChatMessage `json:"delta,omitempty"` // 流式响应中使用
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// ChatMessage 单条消息结构
type ChatMessage struct {
	Role    string `json:"role"` // system/user/assistant
	Content string `json:"content"`
}

// 可选：工具调用相关结构（当使用函数调用功能时）
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // 通常是 "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// 包含工具调用的消息结构
type ChatMessageWithTools struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

func GetMd(charContent string, key string, api string, model string, prompts string) (string, error) {
	requestData := map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{
				"role": "system",
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": prompts,
					},
				},
			},
			{"role": "user", "content": charContent},
		},
		"stream": false,
	}

	// 将数据编码为JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("JSON编码错误:", err)
		return "", err
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", api, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求错误:", err)
		return "", err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求发送错误:", err)
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应错误:", err)
		return "", err
	}
	var completion ChatCompletionResponse
	if err := json.Unmarshal(body, &completion); err != nil {
		log.Fatalf("JSON解析失败: %v", err)
	}
	return completion.Choices[0].Message.Content, err
}
