package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	certs   [][]byte            = [][]byte{}
	blocks  []*pem.Block        = []*pem.Block{}
	x509s   []*x509.Certificate = []*x509.Certificate{}
	lineStr string              = "----------"
	// order   []int               = []int{}
	x509xIndex        []int               = []int{}
	unreferencedIndex []int               = []int{}
	unreferenced      []*x509.Certificate = []*x509.Certificate{}
)

// 讀取證書檔案
func loadCertFile() bool {
	certPEM, err := os.ReadFile(certFilePath)
	if err != nil {
		log.Println("错误：读取证书文件失败:", err)
		return false
	}
	splitPEMCerts(certPEM)
	var numOK [2]int8 = parseCertificates()
	if numOK[0] == 0 {
		log.Println("错误：未找到有效的证书。")
		return false
	}
	var totalLen int = 0
	for _, c := range certs {
		totalLen += len(c)
	}
	log.Println("文件包含证书数:", numOK[0]+numOK[1], " 有效证书数:", numOK[0], " 无效证书数:", numOK[1], " 总字节数:", totalLen)
	processCertificates()
	viewCertInfo()
	return true
}

// 解碼證書
func splitPEMCerts(certChain []byte) [2]int8 {
	var r [2]int8 = [2]int8{0, 0}
	for {
		// 解碼第一個證書
		block, rest := pem.Decode(certChain)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			r[1]++
			log.Println("错误：未知或不正确的 PEM 块类型:", block.Type)
		}
		// 將證書編碼回 PEM 格式並新增到切片中
		certPEM := pem.EncodeToMemory(block)
		certs = append(certs, certPEM)
		blocks = append(blocks, block)
		// 準備下一個證書
		r[0]++
		certChain = rest
	}
	return r
}

// 解析證書
func parseCertificates() [2]int8 {
	var r [2]int8 = [2]int8{0, 0}
	for i, block := range blocks {
		if block == nil {
			r[1]++
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			r[1]++
			log.Println("错误：解析证书失败:", i, err)
			continue
		}
		x509s = append(x509s, cert)
		r[0]++
	}
	return r
}

// 開始處理證書
func processCertificates() {
	var isOk bool = false
	var oldLen int
	for i, cert := range x509s {
		isOkN, x509xIndexN := sortCertificates(cert)
		if len(x509xIndexN) > 0 && x509xIndexN[0] != i && len(x509xIndexN) == len(x509s)-1 {
			x509xIndexN = append([]int{i}, x509xIndexN...)
		}
		// fmt.Println("证书顺序:", i, isOkN, x509xIndexN, "基于:", cert.Subject)
		if i == 0 || len(x509xIndexN) > oldLen {
			oldLen = len(x509xIndexN)
			x509xIndex = x509xIndexN
			isOk = isOkN
		}
	}
	if len(x509s) == 0 || (!isOk && len(x509xIndex) != len(x509s)) {
		log.Println("警告：证书文件不构成完整链。")
	}
	log.Println("证书链:")
	for i, d := range x509xIndex {
		var cert *x509.Certificate = x509s[d]
		var subso string = "└─"
		if i == 0 {
			subso = ""
		}
		fmt.Printf("[%d] %s%s %s (%d B)\n", i, strings.Repeat("  ", i), subso, cert.Subject, len(certs[d]))
	}
	unreferenced = findUnreferencedCerts(x509s, x509xIndex)
	if len(unreferenced) > 0 {
		log.Println("警告：未链接的证书:")
		for i, cert := range unreferenced {
			fmt.Println(i, cert.Subject)
		}
		for _, cert := range unreferenced {
			for i, c := range x509s {
				if cert == c {
					unreferencedIndex = append(unreferencedIndex, i)
					break
				}
			}
		}
	}

	if exitPause {
		fmt.Println("按回车键保存拆分后的证书文件；按 Ctrl+C 退出。")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		saveSubCertFile()
	} else {
		saveSubCertFile()
	}

}

func saveSubCertFile() {
	for i, d := range x509xIndex {
		saveSubCertFileN(i, d, true)
	}
	for i, d := range unreferencedIndex {
		saveSubCertFileN(i, d, false)
	}
}

func saveSubCertFileN(i int, d int, n bool) {
	var cert *x509.Certificate = x509s[d]
	var subjects []string = strings.Split(cert.Subject.String(), ",")

	if len(outputDir) > 0 {
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			err := os.Mkdir(outputDir, 0755)
			if err != nil {
				fmt.Println("错误：创建文件夹失败:", outputDir, err)
				return
			}
		}
	}

	for _, subject := range subjects {
		if len(subject) <= 3 {
			continue
		}
		var subjectInfos []string = strings.Split(subject, "=")

		if subjectInfos[0] == "CN" {
			var di string = strconv.Itoa(i)
			if !n {
				di = "N"
			}
			var fileName string = fmt.Sprintf("%s/%s-%s.pem", outputDir, di, strings.ReplaceAll(subjectInfos[1], " ", "_"))
			var info string = fmt.Sprintf("%s (%d B)", fileName, len(certs[d]))
			if len(outputDir) > 0 {
				err := os.WriteFile(fileName, certs[d], 0644)
				if err != nil {
					log.Printf("错误：写入证书文件 %d: %s 失败: %v\n", i, info, err)
				} else {
					log.Printf("已写入证书文件 %d: %s\n", i, info)
				}
			}
			break
		}
	}
}

func viewCertInfo() {
	if !verbose {
		return
	}
	for i, cert := range x509s {
		fmt.Println("\n", lineStr, "证书", i+1, "/", len(x509s), lineStr)
		fmt.Printf("版本: %d\n", cert.Version)
		fmt.Printf("序列号: %d\n", cert.SerialNumber)
		fmt.Printf("签名算法: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("颁发者(%s): %s\n", bytesMD5(cert.RawIssuer), cert.Issuer)
		fmt.Printf("使用者(%s): %s\n", bytesMD5(cert.RawSubject), cert.Subject)
		fmt.Printf("有效期开始时间: %s\n", cert.NotBefore)
		fmt.Printf("有效期结束时间: %s\n", cert.NotAfter)
		fmt.Printf("公钥算法: %s\n", cert.PublicKeyAlgorithm)
		fmt.Printf("签名: %x\n", cert.Signature)
		fmt.Printf("是否是CA证书: %v\n", cert.IsCA)
		fmt.Printf("最大路径长度: %d\n", cert.MaxPathLen)
		fmt.Printf("主题密钥标识符: %x\n", cert.SubjectKeyId)
		fmt.Printf("授权密钥标识符: %x\n", cert.AuthorityKeyId)
		fmt.Printf("密钥用途: %v\n", cert.KeyUsage)
		fmt.Printf("扩展密钥用途: %v\n", cert.ExtKeyUsage)
		fmt.Printf("基本约束: %t\n", cert.BasicConstraintsValid)
		fmt.Printf("DNS名称: %v\n", cert.DNSNames)
		fmt.Printf("电子邮件地址: %v\n", cert.EmailAddresses)
		fmt.Printf("IP地址: %v\n", cert.IPAddresses)
		fmt.Printf("URI: %v\n", cert.URIs)
		fmt.Printf("CRL分发点: %v\n", cert.CRLDistributionPoints)
		fmt.Printf("OCSP服务器: %v\n", cert.OCSPServer)
		fmt.Printf("证书策略: %v\n", cert.PolicyIdentifiers)
	}
}
