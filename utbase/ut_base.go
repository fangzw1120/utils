package utbase

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// TraceIDKey ...
type TraceIDKey struct{}

// GetTraceID ...
// @Description: TraceID 带到上下文
// @param ctx
// @return string
func GetTraceID(ctx context.Context) string {
	traceID, ok := ctx.Value(TraceIDKey{}).(string)
	if !ok {
		return ""
	}
	return traceID
}

// SetTraceID ...
// @Description: TraceID 带到上下文
// @param ctx
// @param traceID
// @return context.Context
func SetTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey{}, traceID)
}

// GetMainDirectory 获取进程所在目录: 末尾带反斜杠
func GetMainDirectory() string {
	if len(os.Args) == 0 {
		return ""
	}
	path, err := filepath.Abs(os.Args[0])

	if err != nil {
		return ""
	}

	fullPath := filepath.Dir(path)
	return pathAddBackslash(fullPath)
}

// pathAddBackslash 路径最后添加反斜杠
func pathAddBackslash(path string) string {
	i := len(path) - 1

	if !os.IsPathSeparator(path[i]) {
		path += string(os.PathSeparator)
	}
	return path
}

// IsAbsolutePath 是否是绝对路径，只检查开头
func IsAbsolutePath(path string) bool {
	return path != "" && path[0] == '/' && filepath.IsAbs(path)
}

// HashMD5 哈希
func HashMD5(data []byte) string {
	// HashShortMD5 [8:24]
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// ShortHashMd5 前8个字符作为短哈希
func ShortHashMd5(input string) string {
	hasher := md5.New()
	hasher.Write([]byte(input))
	hash := hasher.Sum(nil)
	shortHash := hex.EncodeToString(hash)[:8] // 取前8个字符作为短哈希
	return shortHash
}

// ExecCmd executes the given command
func ExecCmd(c string, args ...string) (string, error) {
	cmd := exec.Command(c, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "exec result empty", nil
	}
	s := string(out)
	return strings.ReplaceAll(s, "\n", ""), nil
}

// KeyFileRead read wg key from file
func KeyFileRead(fileName string) (string, error) {
	pub, err := os.ReadFile(fileName) // just pass the file name
	if err != nil {
		return "", err
	}
	key := string(pub) // convert content to a 'string'
	key = strings.TrimSuffix(key, "\n")
	return key, nil
}

// KeyFileWrite wg key to file
func KeyFileWrite(fileName string, key string) error {
	err := ioutil.WriteFile(fileName, []byte(key), 0666)
	if err != nil {
		return err
	}
	return nil
}

// Powerf x^n
func Powerf(x float64, n int) float64 {
	if n == 0 {
		return 1
	}
	return x * Powerf(x, n-1)
}

// FILE ...
func FILE(n int) string {
	if n <= 0 {
		n = 2
	}
	_, file, _, _ := runtime.Caller(n)
	return file
}

// LINE ...
func LINE(n int) string {
	if n <= 0 {
		n = 2
	}
	_, _, line, _ := runtime.Caller(n)
	return strconv.Itoa(line)
}
