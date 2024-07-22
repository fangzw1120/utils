package utnet

import (
	"bytes"
	"compress/gzip"
	"crypto/rc4"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

const (
	vary              = "Vary"
	AcceptEncoding    = "Accept-Encoding"
	AcceptEncodingEx  = "Accept-EncodingEx"
	ContentEncoding   = "Content-Encoding"
	ContentEncodingEx = "Content-EncodingEx"
	ContentLength     = "Content-Length"
)

var zippers = sync.Pool{}
var unZippers = sync.Pool{}

// 初始化
func init() {
	zippers = sync.Pool{
		New: func() interface{} {
			wr := gzip.NewWriter(nil)
			return &CompressWriter{gzipWriter{wr}}
		}}

	unZippers = sync.Pool{New: func() interface{} {
		buf := []byte{31, 139, 8, 0, 0, 0, 0, 0, 0, 255}
		rbuf := bytes.NewReader(buf)
		wr, err := gzip.NewReader(rbuf)
		return &CompressReader{gzipReader{wr}, err}
	}}
}

// /////////// CompressWriter /////////////////
type gzipWriter struct {
	*gzip.Writer
}

// CompressWriter ...
type CompressWriter struct {
	gzipWriter
}

// NewCompressWriter ...
func NewCompressWriter(w io.Writer) *CompressWriter {
	wr := zippers.Get().(*CompressWriter)
	wr.Reset(w)
	return wr
}

// Close ...
func (gw *CompressWriter) Close() error {
	e := gw.gzipWriter.Close()
	zippers.Put(gw)
	return e
}

// /////////// CompressReader /////////////////
type gzipReader struct {
	*gzip.Reader
}

// CompressReader ...
type CompressReader struct {
	gzipReader
	e error
}

// NewCompressReader ...
func NewCompressReader(r io.Reader) (*CompressReader, error) {
	gr := unZippers.Get().(*CompressReader)
	if gr.e != nil {
		return nil, gr.e
	}
	_ = gr.Reset(r)
	return gr, nil
}

// Close ...
func (gr *CompressReader) Close() error {
	if gr.gzipReader.Reader == nil {
		return errors.New("gr.gzipReader.Reader is nil")
	}
	e := gr.gzipReader.Close()
	unZippers.Put(gr)
	return e
}

// SetCompressHeader ...
func SetCompressHeader(rspWriter http.ResponseWriter) {
	rspWriter.Header().Set(ContentEncodingEx, "gzip")
	rspWriter.Header().Add(vary, AcceptEncodingEx)
	rspWriter.Header().Del(ContentLength)
}

// ShouldUnCompressForOfficial ...
func ShouldUnCompressForOfficial(req *http.Request) bool {
	acceptGzip := false
	for _, encoding := range strings.Split(req.Header.Get(ContentEncoding), ",") {
		if "gzip" == strings.TrimSpace(encoding) {
			acceptGzip = true
			break
		}
	}
	return acceptGzip
}

// ShouldCompress ...
func ShouldCompress(req *http.Request) bool {
	acceptGzip := false
	hdr := req.Header
	for _, encoding := range strings.Split(hdr.Get(AcceptEncodingEx), ",") {
		if "gzip" == strings.TrimSpace(encoding) {
			acceptGzip = true
			break
		}
	}
	return acceptGzip
}

// ShouldUnCompress ...
func ShouldUnCompress(req *http.Request) bool {
	acceptGzip := false
	for _, encoding := range strings.Split(req.Header.Get(ContentEncodingEx), ",") {
		if "gzip" == strings.TrimSpace(encoding) {
			acceptGzip = true
			break
		}
	}
	return acceptGzip
}

// GetUnCompressData 响应解压缩
func GetUnCompressData(data []byte) []byte {
	bc := bytes.NewReader(data)
	gzReader, _ := NewCompressReader(bc)
	if gzReader == nil {
		return nil
	}
	ret, _ := ioutil.ReadAll(gzReader)
	_ = gzReader.Close()
	return ret
}

// GetCompressData 请求压缩
func GetCompressData(data []byte) []byte {
	var ret bytes.Buffer
	zipper := NewCompressWriter(&ret)
	_, _ = zipper.Write(data)
	_ = zipper.Close()
	return ret.Bytes()
}

// ProtocolDecryptV1 响应解密
func ProtocolDecryptV1(data []byte, mid string, seqid uint32) bool {
	return ProtocolEncryptV1(data, mid, seqid)
}

// ProtocolEncryptV1 请求加密
func ProtocolEncryptV1(data []byte, mid string, seqid uint32) bool {
	if len(data) == 0 {
		return true
	}

	key := mid + "FC149CE9B1414613AB6D6C481D95293A"
	key_data := []byte(key)
	for i := 0; i < len(key_data); i++ {
		key_data[i] ^= byte(seqid)
	}

	cipher, err := rc4.NewCipher(key_data)
	if err != nil {
		return false
	}

	cipher.XORKeyStream(data, data)
	return true
}
