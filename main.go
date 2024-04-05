//go:generate goversioninfo -icon=ico/icon.ico -manifest=main.exe.manifest -arm=true
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	certFilePath string
	verbose      bool
	outputDir    string
	exitPause    bool
)

func main() {
	log.Println("SSLCertificateSplittingTool v1.0.0")
	log.Println("https://github.com/tongdysoft/SSLCertificateSplittingTool")

	flag.StringVar(&certFilePath, "i", "", "要加载的 X509 证书文件路径。")
	flag.StringVar(&outputDir, "o", "./out", "输出目录，不带最后的 `/` 。为空则不保存文件。默认路径为 `./out` 。")
	flag.BoolVar(&verbose, "v", false, "显示证书的详细信息。")
	flag.BoolVar(&exitPause, "pa", false, "写入文件前和执行完毕后暂停。如果第一个参数为 X509 证书文件路径（打开方式）则此项强制开启。")
	flag.Parse()

	if len(os.Args) >= 2 && (strings.Contains(os.Args[1], ".")) {
		certFilePath = os.Args[1]
		exitPause = true
	}

	if len(certFilePath) == 0 {
		log.Println("错误：证书文件路径不能为空。")
		pauseExit()
		os.Exit(1)
	}

	if !loadCertFile() {
		pauseExit()
		os.Exit(1)
	}

	pauseExit()
}

func pauseExit() {
	if exitPause {
		fmt.Println("按回车键退出。")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}
