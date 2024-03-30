package main

import (
	"flag"
	"log"
	"os"
)

var (
	certFilePath string
	verbose      bool
	outputDir    string
)

func main() {
	log.Println("SSLCertificateSplittingTool v1.0.0")
	log.Println("https://github.com/tongdysoft/SSLCertificateSplittingTool")

	flag.StringVar(&certFilePath, "i", "", "要加载的 X509 证书文件路径。")
	flag.StringVar(&outputDir, "o", "./out", "输出目录，不带最后的 `/` 。为空则不保存文件。")
	flag.BoolVar(&verbose, "v", false, "显示证书的详细信息。")
	flag.Parse()

	if len(certFilePath) == 0 {
		log.Println("错误：证书文件路径不能为空。")
		os.Exit(1)
	}

	if !loadCertFile() {
		os.Exit(1)
	}
}
