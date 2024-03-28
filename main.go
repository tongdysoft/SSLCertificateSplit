package main

import (
	"flag"
	"log"
	"os"
)

var (
	certFilePath string
	verbose      bool
)

func main() {
	log.Println("SSLCertificateSplittingTool v0.0.1")
	log.Println("https://github.com/tongdysoft/SSLCertificateSplittingTool")

	flag.StringVar(&certFilePath, "i", "", "要加载的证书文件路径。")
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
