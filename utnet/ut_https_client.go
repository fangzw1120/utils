package utnet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/smallnest/rpcx/log"
)

var httpsCli *http.Client
var httpsCliMu sync.RWMutex

func GetHTTPsClient() *http.Client {
	httpsCliMu.RLock()
	defer httpsCliMu.RUnlock()
	return httpsCli
}

func HttpsRequestInit(clientKeyFile, clientCertFile, rootCertFile string) error {
	// ca证书
	caCert, err := os.ReadFile(rootCertFile)
	if err != nil {
		log.Errorf("Error reading CA certificate: %v", err)
		return err
	}

	// 创建一个新的 CertPool，并将自签名根证书添加到其中
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Errorf("Error appending CA certificate to CertPool")
		return err
	}

	// 加载客户端证书和私钥
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		log.Errorf("Failed to load client certificate and key:", err)
		return err
	}

	// 创建客户端的 TLS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}

	httpsCliMu.Lock()
	defer httpsCliMu.Unlock()
	httpsCli = &http.Client{Transport: tr, Timeout: time.Second * 10}
	return nil
}

var httpCli *http.Client
var httpCliMu sync.RWMutex

func GetHTTPClient() *http.Client {
	httpCliMu.RLock()
	defer httpCliMu.RUnlock()
	return httpCli
}

func HttpRequestInit() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}

	httpCli = &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

// HTTPAPIRequestV1 HTTP请求和解析响应，支持头部信息，支持加解密，压缩解压缩
func HTTPAPIRequestV1(cli *http.Client, reqMode string, url string, headers map[string]string, data []byte) ([]byte, error) {
	var resp *http.Response
	var req *http.Request
	var err error
	seqid := uint32(0)
	// 处理头信息
	if val, ok := headers["Content-Seq"]; ok {
		value, _ := strconv.ParseUint(val, 10, 0)
		seqid = uint32(value)
	}
	mid := ""
	if val, ok := headers["Client-Mid"]; ok {
		mid = val
	}
	if val, ok := headers[ContentEncodingEx]; ok {
		if val == "gzip" {
			// 发送内容压缩
			data = GetCompressData(data)
		}
	}
	if val, ok := headers["Content-Encrypt"]; ok {
		if val == "v1" {
			// 发送内容加密
			ProtocolEncryptV1(data, mid, seqid)
		}
	}

	// 根据method生成请求
	if reqMode == "POST" {
		reader := bytes.NewReader(data)
		req, err = http.NewRequest(reqMode, url, reader)
	} else {
		req, err = http.NewRequest(reqMode, url, nil)
	}
	if err != nil {
		err = fmt.Errorf("http NewRequest , Error : %s", err.Error())
		return nil, err
	}
	// 主动关闭请求
	req.Close = true
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")

	if len(headers) > 0 {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// 执行请求
	resp, err = cli.Do(req)
	if err != nil {
		err = fmt.Errorf("Get Do, Error : %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// 解析响应
	if resp == nil {
		err = fmt.Errorf("Request Url : %s, resp == nil", url)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_, err = io.ReadAll(resp.Body)
		err = fmt.Errorf("Request Url : %s, Error Status : %d", url, resp.StatusCode)
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("read body Error : %s", err.Error())
		return nil, err
	}

	// 响应解密
	if val, ok := headers["Content-Encrypt"]; ok {
		if val == "v1" {
			ProtocolDecryptV1(body, mid, seqid)
		}
	}
	// 响应解压缩
	if val, ok := headers[AcceptEncodingEx]; ok {
		if val == "gzip" {
			body = GetUnCompressData(body)
		}
	}
	return body, nil
}
