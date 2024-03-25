package main

import (
	"flag"
	"log"
	"os"
	"runtime"
)

var (
	certFilePath  string
	maxGoroutines int = 1
)

func main() {
	log.Println("SSLCertificateSplittingTool v0.0.1")

	flag.StringVar(&certFilePath, "o", "", "要加载的证书文件路径。")
	flag.Parse()

	maxGoroutines = runtime.NumCPU()

	if len(certFilePath) == 0 {
		log.Println("错误：证书文件路径不能为空。")
		os.Exit(1)
	}

	if !loadCertFile() {
		os.Exit(1)
	}
}
