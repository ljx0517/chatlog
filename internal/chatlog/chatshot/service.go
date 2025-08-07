package chatshot

import (
	"encoding/json"
	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/internal/chatlog/database"
	"github.com/sjzar/chatlog/internal/llm"
	"github.com/sjzar/chatlog/internal/md2pic"
	"github.com/sjzar/chatlog/pkg/util"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var md = `### 微信群「💰💰💰绘玩小卖部」8月5日荒诞日报  
**日期**：2025年8月5日（星期二）  
**核心事件**：光头淋雨引发哲学思考，李老板喜提"当代齐白石"称号  
**总消息量**：29条（含13笔神秘转账 + 3场视觉骗局）  

---

#### 一、今日魔幻头条  
1. **转账迷雾剧场**（全天候）  
   - 全天惊现**13笔幽灵转账**（均显示"当前微信版本不支持"），玉弟锐评："今日消费前三名"（暗示春春或成隐形冠军）  
   - **转账狂魔排行榜**：  
     | 选手                | 转账次数 | 可疑指数 |  
     |---------------------|----------|----------|  
     | 于春春             | 2        | 🌟🌟🌟🌟（零花钱疑云） |  
     | 李维飙             | 2        | 🌟🌟🌟（老板自刷嫌疑） |  
     | 王先生/柳江南等9人 | 各1次    | 🌟🌟       |  

2. **光头淋雨悬疑剧**（15:23-15:34）  
   - 玉弟投喂猛料：**光头壮汉雨中漫步图**  
   - 群友破案现场：  
     > 鲨鱼女士："为啥不打伞？"  
     > 玉弟："没头发不怕淋雨" ← 年度最佳逻辑奖  
     > 阿燃神补刀："他有大头"（物理防御MAX）  

3. **李老板艺术人生**（17:13-17:28）  
   - 李维飙晒**窗台小鸟写真**（配文："放走了"）  
   - 郭宇航发动捧杀技："放根笔以为是你画的"  
   - 李老板光速膨胀：  
     > "有被赞美到" → 立即晒**铅笔鸟合成图**  
     > 酥鱼封神："神笔马良"  
     > 李维飙自封："当代齐白石"（建议申报诺贝尔美术奖）  

---

#### 二、成员行为艺术鉴定  

` + "```mermaid" + `
	pie
	title 话题热度争霸赛
	"幽灵转账" : 45
	"光头淋雨案" : 30
	"李老板艺术展" : 25
` + "```" + `


1. **活跃分子侧写**（大师毒舌版）  
   - **李维飙**：  
     > 从"小卖部老板"进化为"幻术艺术家"，靠窗台小鸟图实现职场转型。  
     > 对"神笔马良"称号照单全收，暴露中年男性终极梦想——不靠产品靠才艺。  
   - **玉弟**：  
     > 人形监控探头，精准捕捉"消费前三"和"淋雨光头"。  
     > 用"没头发不怕淋"破解世纪谜题，爱因斯坦直呼内行。  
   - **郭宇航**：  
     > 捧杀学十级学者，一根铅笔引爆老板艺术魂。  
     > 深藏功与名："去有广锴的群再说一遍"（职场甩锅教科书）。  
   - **刘洋**：  
     > 山楂奶成瘾患者，执着寻找"金豆芽"儿童奶。  
     > 晒图反被嘲"你被骗了"，当代网购受害者缩影。  

---

#### 三、关键战役全纪录  
1. **15:24 山楂奶暴动事件**  
   - 刘洋："我想喝山楂味小孩奶！"（配幼崽奶瓶图）  
   - 郭宇航秒拆台："那叫金豆芽"（命名权争夺战）  
   - 结局：无人代购，刘洋遭遇"奶圈诈骗"  

2. **17:21 铅笔骗局时间线(艺术诈骗全流程)**  
- 17:13 ： 李老板晒真鸟图  
- 17:14 ： KIKI预警"别飞了"  
- 17:21 ： 郭宇航埋笔"以为是你画的"  
- 17:22 ： 李老板接梗"广锴不在本群"（甩锅预备）  
- 17:23 ： 晒铅笔鸟合成图（犯罪证据）  
- 17:25 ： 酥鱼定性"神笔马良"  
- 17:28 ： 李老板自封"当代齐白石"  

---

#### 四、神秘数据透视  
1. **转账时段玄学**  
   | 时间段   | 转账量 | 可能真相                |  
   |----------|--------|-------------------------|  
   | 9:00-10:00 | 4      | 晨会摸鱼资金            |  
   | 10:33    | 2      | 柳江南&王先生对冲交易   |  
   | 14:58    | 2      | 春春最后的零花钱        |  

2. **视觉诈骗档案**  
   | 图片内容         | 提供者       | 群友被骗反应            |  
   |------------------|--------------|-------------------------|  
   | 光头淋雨男       | 玉弟         | 鲨鱼女士思考人生        |  
   | 窗台真鸟        | 李维飙       | 郭宇航误认水墨画        |  
   | 铅笔+鸟合成图   | 李维飙       | 全员配合演出"当代齐白石" |  

---

#### 五、暴言总结  
1. 本群转账记录堪比CIA机密文件，"高频率转账"成最佳防审计屏障  
2. 光头淋雨图证明：职场防秃=自带雨伞功能，人力部应纳入福利体系  
3. 李老板用"铅笔鸟图"实现从商人到艺术家的阶级跃迁，建议小卖部改画廊  
4. 刘洋的山楂奶之梦碎警示：成年人的童心总被现实毒打  

> 本日报由「绘玩脑洞研究所」赞助播出：  
> *"当转账不可见时，万物皆可成为艺术品！"*`

type Service struct {
	ctx *ctx.Context
	db  *database.Service
}

func NewService(ctx *ctx.Context, db *database.Service) *Service {
	return &Service{
		ctx: ctx,
		db:  db,
	}
}
func (s *Service) Shot() error {

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
		s.GenerateReport(llmConfig, s.db)
	}

	return nil
}

func (s *Service) GenerateReport(cfg util.LLMConfig, db *database.Service) error {
	var q = struct {
		Time    string `form:"time"`
		Talker  string `form:"talker"`
		Sender  string `form:"sender"`
		Keyword string `form:"keyword"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}
	var talkers = strings.Split(cfg.Talkers, ",")
	now := time.Now()
	timeStr := now.Format("20060102150405")
	dateStr := now.Format("2006-01-02")
	q.Time = dateStr

	var start, end, _ = util.TimeRangeOf(q.Time)

	//md2pic.Md2Pic("_"+dateStr, md)
	//return errors.New("test finished")

	for _, talker := range talkers {
		if talker == "" {
			continue
		}
		savePath := filepath.Join(dateStr, util.FormatValidFilename(talker, 50))
		saveName := util.FormatValidFilename(talker, 50) + "_" + timeStr
		util.EnsureDirExists(savePath, 0755)
		var messages, _ = db.GetMessages(start, end, talker, "", "", 0, 0)
		if len(messages) == 0 {
			continue
		}
		var merged = append([]string{}, "")
		for _, m := range messages {
			var msg = m.PlainText(strings.Contains(q.Talker, ","), util.PerfectTimeFormat(start, end), "")
			merged = append(merged, msg)
		}
		var content = strings.Join(merged, "\n")
		var md, _ = llm.GetMd(content, cfg.Key, cfg.Api, cfg.Model, cfg.Prompts)

		md2pic.Md2Pic(md, savePath, saveName)
	}
	return nil
}
