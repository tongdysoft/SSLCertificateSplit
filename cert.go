package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

var (
	certs   [][]byte            = [][]byte{}
	blocks  []*pem.Block        = []*pem.Block{}
	x509s   []*x509.Certificate = []*x509.Certificate{}
	lineStr string              = "----------"
)

func loadCertFile() bool {
	// 读取证书文件
	certPEM, err := os.ReadFile(certFilePath)
	if err != nil {
		log.Println("错误：读取证书文件失败:", err)
		return false
	}
	splitPEMCerts(certPEM)
	var numOK [2]int8 = parseCertificates()
	log.Println("文件包含证书数:", numOK[0]+numOK[1], " 有效证书数:", numOK[0], " 无效证书数:", numOK[1])
	viewCertInfo()
	return true
}

func splitPEMCerts(certChain []byte) [2]int8 {
	var r [2]int8 = [2]int8{0, 0}
	for {
		// 解码第一个证书
		block, rest := pem.Decode(certChain)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			r[1]++
			log.Println("错误：未知的PEM块类型:", block.Type)
		}
		// 将证书编码回PEM格式并添加到切片中
		certPEM := pem.EncodeToMemory(block)
		certs = append(certs, certPEM)
		blocks = append(blocks, block)
		// 准备下一个证书
		r[0]++
		certChain = rest
	}
	return r
}

func parseCertificates() [2]int8 {
	var r [2]int8 = [2]int8{0, 0}
	for i, block := range blocks {
		if block == nil {
			r[1]++
			continue
		}
		// 解析证书
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

func viewCertInfo() bool {
	if len(x509s) == 0 {
		log.Println("错误：没有证书可供查看。")
		return false
	}
	for i, cert := range x509s {
		fmt.Println("\n", lineStr, "证书", i+1, "/", len(x509s), lineStr)
		fmt.Printf("版本: %d\n", cert.Version)
		fmt.Printf("序列号: %d\n", cert.SerialNumber)
		fmt.Printf("签名算法: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("颁发者: %s\n", cert.Issuer)
		fmt.Printf("使用者: %s\n", cert.Subject)
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
	return true
}
