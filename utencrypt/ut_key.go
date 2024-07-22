package utencrypt

import (
	"encoding/base64"

	"github.com/smallnest/rpcx/log"
)

// IsPubKeyValid 验证公私钥是否合法，主要用于l3
func IsPubKeyValid(pubKey string) bool {
	// 解码 Base64 公钥
	decodedKey, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		log.Errorf("DecodeString %+v, err %+v", pubKey, err)
		return false
	}

	// 验证解码后的公钥长度
	if len(decodedKey) != 32 {
		log.Errorf("len(decodedKey) %+v, err", pubKey)
		return false
	}
	return true
}
