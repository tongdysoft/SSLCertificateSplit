package main

import (
	"crypto/md5"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"strings"
)

// 返回 certs 中未被 indexes 引用的元素
func findUnreferencedCerts(certs []*x509.Certificate, indexes []int) []*x509.Certificate {
	indexMap := make(map[int]bool)
	for _, index := range indexes {
		indexMap[index] = true
	}

	var unreferenced []*x509.Certificate
	for i, certs := range certs {
		if _, found := indexMap[i]; !found {
			unreferenced = append(unreferenced, certs)
		}
	}

	return unreferenced
}

// 返回正確的證書鏈順序作為整數陣列
func sortCertificates(rootCert *x509.Certificate) (bool, []int) {
	// var order []int
	var x509xIndex []int = []int{}
	var isOK bool = true
	var endSub string = bytesMD5(rootCert.RawSubject) //bytesMD5(rootCert.RawSubject)
	var forMax = len(x509s) + 1
	for m := 0; m < forMax; m++ {
		for i, cert := range x509s {
			if bytesMD5(cert.RawIssuer) == endSub {
				if bytesMD5(cert.RawIssuer) == bytesMD5(cert.RawSubject) {
					if len(x509xIndex) == 0 {
						x509xIndex = append(x509xIndex, i)
					}
				} else {
					x509xIndex = append(x509xIndex, i)
					endSub = bytesMD5(cert.RawSubject)
					break
				}
			}
		}
		if len(x509xIndex) == len(x509s) {
			break
		}
		if m >= len(x509s) {
			isOK = false
		}
	}
	return isOK, x509xIndex
}

func bytesMD5(b []byte) string {
	return fmt.Sprintf("%x", md5.Sum(b))
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
						log.Println("根证书:\n    颁发者:", cert.Issuer, "\n    使用者:", cert.Subject)
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
