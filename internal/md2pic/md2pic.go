package md2pic

import (
	"bytes"
	"context"
	_ "embed"
	"go.abhg.dev/goldmark/mermaid"
	"go.abhg.dev/goldmark/mermaid/mermaidcdp"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/yuin/goldmark"
)

//go:embed  mermaid.min.js
var mermaidJSSource string

func hexStrToChar(hexStr []int32) (string, error) {
	// 去除可能的 "0x" 或 "0X" 前缀
	//hexStr = strings.TrimPrefix(hexStr, "0x")
	//hexStr = strings.TrimPrefix(hexStr, "0X")

	// 解析十六进制字符串为整数（基数 16）
	//codePoint, err := strconv.ParseInt(hexStr, 16, 32) // 32位确保覆盖常用Unicode范围
	//if err != nil {
	//	return 0, fmt.Errorf("无效的十六进制字符串: %v", err)
	//}
	var cps []string
	for _, c := range hexStr {
		//var codePoint, err = strconv.ParseInt(c, 16, 32)
		cps = append(cps, string(c))
	}

	// 转换为 rune（Unicode 码点）
	return strings.Join(cps, ""), nil
}

func Md2Pic(mdContent string, savePath string, saveName string) error {
	name := filepath.Join(savePath, saveName)
	// 1. 读取 Markdown 文件
	//mdContent, err := os.ReadFile("input.md")
	//if err != nil {
	//	panic(err)
	//}

	mdContent = strings.TrimPrefix(mdContent, "```markdown")
	mdContent = strings.TrimSuffix(mdContent, "```")
	if err := os.WriteFile(name+".md", []byte(mdContent), 0644); err != nil {
		return err
	}
	// 2. 将 Markdown 转换为 HTML
	htmlContent, err := convertMarkdownToHTML([]byte(mdContent))
	if err != nil {
		return err
	}
	if err := os.WriteFile(name+".html", htmlContent, 0644); err != nil {
		return err
	}

	// 3. 使用 ChromeDP 生成图片
	imgData, err := convertHTMLToImage(htmlContent)
	if err != nil {
		return err
	}

	// 4. 保存图片
	if err := os.WriteFile(name+".png", imgData, 0644); err != nil {
		return err
	}
	return nil
}

// Markdown 转 HTML
func convertMarkdownToHTML(md []byte) ([]byte, error) {
	//<script>
	//	mermaid.initialize({
	//theme: 'default',
	//	fontFamily: '-apple-system, "Times New Roman","Microsoft YaHei","KaiTi",Georgia,Serif, BlinkMacSystemFont, "Segoe WPC", "Segoe UI", "Ubuntu", "Droid Sans", sans-serif, "Meiryo", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"'
	//});
	//</script>

	//<style>
	//	body { font-family: -apple-system, "Times New Roman","Microsoft YaHei","KaiTi",Georgia,Serif, BlinkMacSystemFont, "Segoe WPC", "Segoe UI", "Ubuntu", "Droid Sans", sans-serif, "Meiryo", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; line-height: 1.6 }
	//code { background: #f8f8f8; padding: 2px 5px }
	//pre { background: #2d2d2d; color: #f8f8f2; padding: 10px }
	//</style>

	var head = `<!DOCTYPE html><html lang="zh-cn"><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
</head><body>`
	var foot = `
</body></html>`
	compiler, err := mermaidcdp.New(&mermaidcdp.Config{
		JSSource: mermaidJSSource,
	})
	if err != nil {
		panic(err)
	}
	defer compiler.Close()
	var buf bytes.Buffer
	if err := goldmark.New(
		goldmark.WithExtensions(
			// ...
			&mermaid.Extender{
				//RenderMode: mermaid.RenderModeClient,
				Compiler: compiler,
			},
		),
		// ...
	).Convert(md, &buf); err != nil {
		return nil, err
	}
	return []byte(head + buf.String() + foot), nil
}

// HTML 转 PNG 图片
func convertHTMLToImage(htmlContent []byte) ([]byte, error) {
	//var opts = []chromedp.{
	//	chromedp.WindowSize(1280, 720), // 设置窗口大小，避免渲染不全
	//	//chromedp.Headless(true),        // 无头模式（服务器环境常用）
	//	// 禁用 GPU（解决部分服务器环境渲染问题）
	//	chromedp.Flag("disable-gpu", true),
	//	// 忽略证书错误（可选，根据需求开启）
	//	chromedp.Flag("ignore-certificate-errors", true),
	//	// 启用日志（调试用）
	//	chromedp.WithDebugf(log.Printf),
	//}

	var opts = append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoDefaultBrowserCheck,                   // 不检查默认浏览器
		chromedp.Flag("headless", true),                  // 开启图像界面（有头模式）
		chromedp.Flag("ignore-certificate-errors", true), // 忽略 SSL 证书错误
		chromedp.Flag("disable-web-security", true),      // 禁用网络安全标志
		chromedp.NoFirstRun,                              // 设置网站不是首次运行
		chromedp.Flag("mute-audio", false),               // 开启声音
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36"), // 设置 User-Agent
	)
	var allocCtx, _ = chromedp.NewExecAllocator(context.Background(), opts...)
	// 创建 Chrome 实例
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// 配置截图参数
	var imgBuf []byte

	//err := chromedp.Run(ctx,
	//	// 设置视口大小
	//	emulation.SetDeviceMetricsOverride(1200, 800, 1.0, false),
	//	// 自定义 CSS
	//	chromedp.Evaluate(`document.body.style.background="linear-gradient(45deg, #f3f4f6, #e5e7eb)";`, nil),
	//	// 截图特定元素
	//	chromedp.Screenshot(`#content`, &imgBuf, chromedp.NodeVisible),
	//)
	//var cc = string(htmlContent)
	//var result string
	//var js, _ = hexStrToChar(Mermaidjs)
	err := chromedp.Run(ctx,
		emulation.SetDeviceMetricsOverride(1280, 800, 2.0, false),
		//emulation.SetUserAgentOverride("Chromedp"),
		//emulation.SetPageScaleFactor(2),

		//chromedp.Navigate("data:text/html,"+string(htmlContent)),
		chromedp.Navigate("about:blank"),
		chromedp.Evaluate(`
            var style = document.createElement('style');
            style.innerHTML = 'body {font-family: -apple-system, "Microsoft YaHei","PingFang SC", Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; line-height: 1.6 }';
            document.head.appendChild(style);
			`, nil),
		//chromedp.Evaluate(js, nil),
		//chromedp.Evaluate(js, &result, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		//	return p.WithAwaitPromise(true)
		//}),
		//chromedp.Navigate("about:blank"),
		//chromedp.Evaluate("document.write(`"+string(htmlContent)+"`)", nil),

		//chromedp.InnerHTML("body", &cc),
		//chromedp.WaitReady("body", chromedp.ByQuery),
		//chromedp.WaitVisible("body", chromedp.ByID),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerHTML=`+"`"+string(htmlContent)+"`", nil),
		chromedp.Sleep(2*time.Second), // 等待渲染
		chromedp.FullScreenshot(&imgBuf, 100),
		//chromedp.Screenshot("body", &imgBuf, chromedp.NodeVisible),
	)

	return imgBuf, err
}
