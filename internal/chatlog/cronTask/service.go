package cronTask

import (
	"encoding/json"
	"fmt"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/chatshot"
	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/pkg/util"
	"os"
)

var entryIDs []cron.EntryID

type Service struct {
	ctx      *ctx.Context
	chatshot *chatshot.Service
	c        *cron.Cron
}

func NewService(ctx *ctx.Context, chatshot *chatshot.Service) *Service {
	return &Service{
		ctx:      ctx,
		chatshot: chatshot,
	}
}

func (s *Service) Stop() error {
	for _, entryID := range entryIDs {
		s.c.Remove(entryID)
	}
	return nil
}

func (s *Service) Start() error {
	//var err = s.chatshot.Shot()
	//return err

	var _, cfgErr = util.IsFile("config.json")
	if cfgErr != nil {
		return cfgErr
	}
	var cfgJsonString, err = os.ReadFile("config.json") // os.ReadFile 会自动打开并关闭文件
	if err != nil {
		// 处理文件读取错误（如文件不存在、权限不足等）
		log.Err(err).Msgf("读取文件失败: %v\n", err)
		return err
	}
	var llmConfigs util.LLMConfigs
	err = json.Unmarshal(cfgJsonString, &llmConfigs)
	if err != nil {
		// 处理 JSON 解析错误（如格式错误、结构不匹配等）
		log.Err(err).Msgf("解析 JSON 失败: %v\n", err)
		return err
	}
	for _, llmConfig := range llmConfigs {
		s.addCronTask(llmConfig)
	}
	return nil
}
func (s *Service) addCronTask(cfg util.LLMConfig) error {
	var entryID, err = s.c.AddFunc(cfg.Cron, func() {
		s.chatshot.Shot()
		fmt.Println("Every hour on the half hour")
	})
	if err != nil {
		entryIDs = append(entryIDs, entryID)
	}
	s.c.Start()

	return nil
}
