package utnet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var httpClient *http.Client

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
	}
	httpClient = &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

// HTTPAPIRequest HTTP请求和解析响应，支持头部信息，支持加解密，压缩解压缩
func HTTPAPIRequest(reqMode string, url string, headers map[string]string, data []byte) ([]byte, error) {
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

	if len(headers) > 0 {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// 执行请求
	resp, err = httpClient.Do(req)
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
		_, err = ioutil.ReadAll(resp.Body)
		err = fmt.Errorf("Request Url : %s, Error Status : %d", url, resp.StatusCode)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
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

// SessionInfo ...
type SessionInfo struct {
	//MidInfo             *stUserPermitInfo
	//AccountInfo         *AccountInfo
	//MidPermit           bool
	ClientIPPort        string
	ClientMid           string
	ClientGuid          string
	ClientVersionString string
	ClientVersion       uint64
	ClientMachine       string
	ProtoVer            uint32
	ProtoCmd            uint32
	ContentEncrypt      string
	ContentSeq          uint32

	ContentType string
	Host        string
	Data        string
	DataByte    []byte

	shouldCompress   bool //是否压缩
	shouldUnCompress bool //是否解压
}

// GetShouldCompress ...
func (si *SessionInfo) GetShouldCompress() bool {
	return si.shouldCompress
}

// GetShouldUnCompress ...
func (si *SessionInfo) GetShouldUnCompress() bool {
	return si.shouldUnCompress
}

// Parse ...
// @Description: parse HTTP request to DataByte
// @receiver si
// @param req
// @return error
func (si *SessionInfo) Parse(req *http.Request) error {
	si.ClientIPPort = req.Header.Get("X-Real-IP")
	if si.ClientIPPort == "" {
		si.ClientIPPort = req.RemoteAddr
	}
	xForwardedFor := req.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		xFwd := strings.Split(xForwardedFor, ",")
		if len(xFwd) != 0 {
			xip := strings.TrimSpace(xFwd[0])
			if xip != "" {
				si.ClientIPPort = xip
			}
		}
	}

	si.ContentSeq = getStringUint32(req.Header.Get("Content-Seq"))
	//if si.ContentSeq == 0 {
	//	return errors.New("The Content-Seq is missing!")
	//}
	si.ProtoVer = getStringUint32(req.Header.Get("Proto-Ver"))

	uri, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return errors.New("req.URL.RawQuery is invalid")
	}
	si.ProtoCmd = getStringUint32(uri.Get("cmd"))
	//si.ClientMid = uri.Get("mid")
	si.ClientMid = req.Header.Get("Client-Mid")
	si.ClientGuid = uri.Get("guid")
	si.ClientVersionString = req.Header.Get("Client-Version")
	si.ClientMachine = req.Header.Get("Client-Machine")
	si.ContentEncrypt = req.Header.Get("Content-Encrypt")
	si.ContentType = req.Header.Get("Content-Type")

	if ip := strings.Split(req.Host, ":"); len(ip) > 0 {
		si.Host = ip[0]
	} else {
		si.Host = req.Host
	}

	var ver1, ver2, ver3, ver4 uint64
	fmt.Sscanf(si.ClientVersionString, "%d.%d.%d.%d", &ver1, &ver2, &ver3, &ver4)
	si.ClientVersion = (ver1 << 48) + (ver2 << 32) + (ver3 << 16) + ver4

	data, err := ioutil.ReadAll(req.Body)
	// pretty print http request
	//reqDump, _ := httputil.DumpRequest(req, false)
	//log.Debugf("[Session] req header\n%s", reqDump)

	/**
	双端与后台对齐 ：同步修改为：先压缩再加密  ==>  对应取数据先解密再解压
	兼容性处理 ：	  采用ProtoVer作为区分，新版本号选用3
	*/
	// 先看是否被nginx压缩过
	if ShouldUnCompressForOfficial(req) {
		// 如果有，先解压
		data = GetUnCompressData(data)
	}
	//是否启用解密
	if si.ContentEncrypt == "v1" {
		if ProtocolDecryptV1(data, si.ClientMid, si.ContentSeq) == false {
			return errors.New("[Session] The request is invalid!")
		}
	}
	//当前请求数据是否启用解压
	if ShouldUnCompress(req) {
		//log.Debugf("[Session] Request data should uncompress")
		si.shouldUnCompress = true
		data = GetUnCompressData(data)
		//log.Debugf("[Session] after GetUnCompressData %+v", data)
	} else {
		//log.Debugf("[Session] X Request data should not uncompress")
	}

	//往后的响应是否启用压缩
	if ShouldCompress(req) {
		//log.Debugf("[Session] resp data should compress")
		si.shouldCompress = true
	} else {
		//log.Debugf("[Session] X resp data should not compress")
	}
	si.Data = Byte2String(data)
	//log.Debugf("[Session] %+v", si)
	si.DataByte = data
	return nil
}

func getStringUint32(data string) uint32 {
	value, _ := strconv.ParseUint(data, 10, 0)
	return uint32(value)
}

// Byte2String ...
func Byte2String(data []byte) string {
	for i, c := range data {
		if c == 0 {
			return string(data[:i])
		}
	}
	return string(data[:])
}
