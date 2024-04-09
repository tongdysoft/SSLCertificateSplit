RD /S /Q test
MKDIR test
CD test

ECHO ca.key
openssl genrsa -out ca.key 2048
ECHO ca.pem
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1 -out ca.pem -subj "/C=CN/ST=Beijing/L=Beijing/O=Tongdy/OU=IT/CN=TongdyCA0/emailAddress=test-ca@tongdy.com"
openssl x509 -in ca.pem -noout -text

ECHO intermediate0.key
openssl genrsa -out intermediate0.key 2048
ECHO intermediate0.csr
openssl req -new -key intermediate0.key -out intermediate0.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Tongdy/OU=IT/CN=TongdyIntermediate0/emailAddress=test-intermediate0@tongdy.com"
ECHO intermediate0.pem
openssl x509 -req -in intermediate0.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out intermediate0.pem -days 1 -sha256
openssl x509 -in intermediate0.pem -noout -text

ECHO intermediate1.key
openssl genrsa -out intermediate1.key 2048
ECHO intermediate1.csr
openssl req -new -key intermediate1.key -out intermediate1.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Tongdy/OU=IT/CN=TongdyIntermediate1/emailAddress=test-intermediate1@tongdy.com"
ECHO intermediate1.pem
openssl x509 -req -in intermediate1.csr -CA intermediate0.pem -CAkey intermediate0.key -CAcreateserial -out intermediate1.pem -days 1 -sha256
openssl x509 -in intermediate1.pem -noout -text

ECHO intermediate2.key
openssl genrsa -out intermediate2.key 2048
ECHO intermediate2.csr
openssl req -new -key intermediate2.key -out intermediate2.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Tongdy/OU=IT/CN=TongdyIntermediate2/emailAddress=test-intermediate2@tongdy.com"
ECHO intermediate2.pem
openssl x509 -req -in intermediate2.csr -CA intermediate1.pem -CAkey intermediate1.key -CAcreateserial -out intermediate2.pem -days 1 -sha256
openssl x509 -in intermediate2.pem -noout -text

for /L %%i in (0,1,3) do (
    echo %%i
    ECHO test%%i.tongdy.com.key
    openssl genrsa -out test%%i.tongdy.com.key 2048

    ECHO test%%i.tongdy.com.csr
    openssl req -new -key test%%i.tongdy.com.key -out test%%i.tongdy.com.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Tongdy/OU=IT/CN=test%%i.tongdy.com/emailAddress=test%%i@tongdy.com"

    ECHO test%%i.tongdy.com.crt
    openssl x509 -req -in test%%i.tongdy.com.csr -CA intermediate2.pem -CAkey intermediate2.key -CAcreateserial -out test%%i.tongdy.com.crt -days 1 -sha256

    ECHO test%%i.tongdy.com-full.crt
    TYPE test%%i.tongdy.com.crt >test%%i.tongdy.com-full.crt
    ECHO. >>test%%i.tongdy.com-full.crt
    TYPE intermediate2.pem >>test%%i.tongdy.com-full.crt
    ECHO. >>test%%i.tongdy.com-full.crt
    TYPE intermediate1.pem >>test%%i.tongdy.com-full.crt
    ECHO. >>test%%i.tongdy.com-full.crt
    TYPE intermediate0.pem >>test%%i.tongdy.com-full.crt
    ECHO. >>test%%i.tongdy.com-full.crt
    TYPE ca.pem >>test%%i.tongdy.com-full.crt
    openssl x509 -in test%%i.tongdy.com-full.crt -noout -text
)

CD ..
go build .
SSLCertificateSplittingTool -i test\ca.pem -o test
SSLCertificateSplittingTool -i test\intermediate0.pem -o test
SSLCertificateSplittingTool -i test\intermediate1.pem -o test
SSLCertificateSplittingTool -i test\intermediate2.pem -o test
SSLCertificateSplittingTool -i test\test0.tongdy.com-full.crt -o test
SSLCertificateSplittingTool -i test\test1.tongdy.com-full.crt -o test
SSLCertificateSplittingTool -i test\test2.tongdy.com-full.crt -o test
