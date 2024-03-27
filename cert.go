package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

var (
	certs   [][]byte            = [][]byte{}
	blocks  []*pem.Block        = []*pem.Block{}
	x509s   []*x509.Certificate = []*x509.Certificate{}
	lineStr string              = "----------"
	order   []int               = []int{}
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
	log.Println("文件包含证书数:", numOK[0]+numOK[1], " 有效证书数:", numOK[0], " 无效证书数:", numOK[1])
	sortCertificates()
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
			log.Println("错误：未知的PEM块类型:", block.Type)
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

// 從字串切片中刪除重複的字串
func uniqueStrings(strings []string) []string {
	// 建立一個對映來記錄每個字串出現的次數
	countMap := make(map[string]int)
	for _, str := range strings {
		countMap[str]++
	}
	// 建立一個空切片來儲存沒有重複的字串
	var unique []string
	for str, count := range countMap {
		// 如果某個字串的出現次數為 1 ，那麼它就是沒有重複的，加入到結果切片中
		if count == 1 {
			unique = append(unique, str)
		}
	}
	return unique
}

// 查詢根證書
func findRootCert() *x509.Certificate {
	for _, cert := range x509s {
		if bytesMD5(cert.RawIssuer) == bytesMD5(cert.RawSubject) {
			fmt.Println("根证书:", cert.Subject, "\n    颁发者&使用者:", cert.Issuer)
			return cert
		}
	}
	log.Println("警告：没有找到根证书，尝试使用第一个 CA 证书作为根证书。")
	var allCNs []string = make([]string, len(x509s)) //*2
	for i, cert := range x509s {
		allCNs[i] = bytesMD5(cert.RawSubject)
		// allCNs[i+len(x509s)] = bytesMD5(cert.RawIssuer)
	}
	allCNs = uniqueStrings(allCNs)
	var allCNcert []*x509.Certificate = []*x509.Certificate{}
	for i, ac := range allCNs {
		for _, cert := range x509s {
			if bytesMD5(cert.RawSubject) == ac {
				allCNcert = append(allCNcert, cert)
				allCNs[i] = cert.Subject.String()
			}
		}
	}
	for _, cert := range allCNcert {
		if cert.IsCA {
			fmt.Println("根证书:", cert.Subject, "\n    颁发者:", cert.Issuer, "\n    使用者:", cert.Subject)
			return cert
		}
	}
	log.Println("警告：没有找到 CA 证书，尝试使用使用者不具有域名的第一个不重复证书作为根证书。")
	for _, cn := range allCNs {
		fmt.Println(cn)
		var host string = strings.Split(cn, "=")[1]
		var hosts []string = strings.Split(host, ",")
		for _, host := range hosts {
			_, err := url.Parse(host)
			if err != nil {
				for _, cert := range x509s {
					if cert.Subject.String() == cn {
						fmt.Println("根证书:", cert.Subject, "\n    颁发者:", cert.Issuer, "\n    使用者:", cert.Subject)
						return cert
					}
				}
			}
		}
	}
	log.Println("警告：没有找到 CA 证书，尝试使用第一个证书作为根证书。")
	fmt.Println("根证书:", x509s[0].Subject, "\n    颁发者:", x509s[0].Issuer, "\n    使用者:", x509s[0].Subject)
	return x509s[0]
}

// 返回正確的證書鏈順序作為整數陣列
func sortCertificates() {
	// var order []int
	var rootCert *x509.Certificate = findRootCert()

	// fmt.Println("order", order)
	// for i, o := range order {
	// 	var cert = x509s[o]
	// 	var subso = "└─"
	// 	if i == 0 {
	// 		subso = ""
	// 	}
	// 	fmt.Println(strings.Repeat("  ", i)+subso, cert.Subject)
	// }
}

func bytesMD5(b []byte) string {
	return fmt.Sprintf("%x", md5.Sum(b))
}

func viewCertInfo() bool {

	for i, cert := range x509s {
		fmt.Println("\n", lineStr, "证书", i+1, "/", len(x509s), lineStr)
		// 	// fmt.Printf("版本: %d\n", cert.Version)
		// 	// fmt.Printf("序列号: %d\n", cert.SerialNumber)
		// 	// fmt.Printf("签名算法: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("颁发者(%s): %s\n", bytesMD5(cert.RawIssuer), cert.Issuer)
		fmt.Printf("使用者(%s): %s\n", bytesMD5(cert.RawSubject), cert.Subject)
		// 	// fmt.Printf("有效期开始时间: %s\n", cert.NotBefore)
		// 	// fmt.Printf("有效期结束时间: %s\n", cert.NotAfter)
		// 	// fmt.Printf("公钥算法: %s\n", cert.PublicKeyAlgorithm)
		// 	// fmt.Printf("签名: %x\n", cert.Signature)
		// 	// fmt.Printf("是否是CA证书: %v\n", cert.IsCA)
		// 	// fmt.Printf("最大路径长度: %d\n", cert.MaxPathLen)
		// 	// fmt.Printf("主题密钥标识符: %x\n", cert.SubjectKeyId)
		// 	// fmt.Printf("授权密钥标识符: %x\n", cert.AuthorityKeyId)
		// 	// fmt.Printf("密钥用途: %v\n", cert.KeyUsage)
		// 	// fmt.Printf("扩展密钥用途: %v\n", cert.ExtKeyUsage)
		// 	// fmt.Printf("基本约束: %t\n", cert.BasicConstraintsValid)
		// 	// fmt.Printf("DNS名称: %v\n", cert.DNSNames)
		// 	// fmt.Printf("电子邮件地址: %v\n", cert.EmailAddresses)
		// 	// fmt.Printf("IP地址: %v\n", cert.IPAddresses)
		// 	// fmt.Printf("URI: %v\n", cert.URIs)
		// 	// fmt.Printf("CRL分发点: %v\n", cert.CRLDistributionPoints)
		// 	// fmt.Printf("OCSP服务器: %v\n", cert.OCSPServer)
		// 	// fmt.Printf("证书策略: %v\n", cert.PolicyIdentifiers)
	}
	return true
}
