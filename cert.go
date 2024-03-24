package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func loadCertFile() bool {
	// 读取证书文件
	certPEM, err := os.ReadFile(certFilePath)
	if err != nil {
		log.Println("错误：读取证书文件失败:", err)
		return false
	}

	// 解析PEM编码的证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Println("错误：解析证书失败")
		return false
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("错误：解析证书失败:", err)
		return false
	}

	// 打印证书信息
	fmt.Println("证书信息:")
	fmt.Printf("版本: %d\n", cert.Version)
	fmt.Printf("序列号: %d\n", cert.SerialNumber)
	fmt.Printf("签名算法: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("颁发者: %s\n", cert.Issuer)
	fmt.Printf("有效期开始时间: %s\n", cert.NotBefore)
	fmt.Printf("有效期结束时间: %s\n", cert.NotAfter)
	fmt.Printf("使用者: %s\n", cert.Subject)
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

	return true
}
