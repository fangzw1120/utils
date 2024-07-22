package utencrypt

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

// KeySize ...
const KeySize = 32

type (
	Key          [KeySize]byte
	PrivateKey   [KeySize]byte
	PublicKey    [KeySize]byte
	PresharedKey [KeySize]byte
)

// New 生成一个新的 PrivateKey
func New() (key PrivateKey, err error) {
	_, err = rand.Read(key[:])
	key.clamp()
	return
}

// clamp ...
// @Description: 调整私钥的某些位，以确保它适用于椭圆曲线算法（如Curve25519）
// @receiver key
func (key *PrivateKey) clamp() {
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
}

// GetPublicKey 使用私钥生成对应的公钥
func (key *PrivateKey) GetPublicKey() (publicKey PublicKey) {
	apk := (*[KeySize]byte)(&publicKey)
	ask := (*[KeySize]byte)(key)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

// SharedSecret 使用私钥和另一个公钥计算一个共享密钥
func (key *PrivateKey) SharedSecret(publicKey PublicKey) (PresharedKey, error) {
	presharedKey, err := curve25519.X25519(key[:], publicKey[:])
	if err != nil {
		return PresharedKey{}, err
	}
	return *(*PresharedKey)(presharedKey), nil
}

// Hex 私钥的十六进制字符串表示形式
func (key *PrivateKey) Hex() string {
	return hex.EncodeToString(key[:])
}

// Hex 公钥的十六进制字符串表示形式
func (key *PublicKey) Hex() string {
	return hex.EncodeToString(key[:])
}

// Hex 预共享密钥的十六进制字符串表示形式
func (key *PresharedKey) Hex() string {
	return hex.EncodeToString(key[:])
}

// Base64 私钥的Base64编码字符串表示形式
func (key *PrivateKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// Base64 公钥的Base64编码字符串表示形式
func (key *PublicKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// Base64 预共享密钥的Base64编码字符串表示形式
func (key *PresharedKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// LoadExactHex ...
func LoadExactHex[T ~[KeySize]byte](src string) (T, error) {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return T{}, err
	}
	if len(slice) != KeySize {
		return T{}, errors.New("hex string does not fit the slice")
	}
	return *(*[KeySize]byte)(slice[:]), nil
}

// LoadExactBase64 ...
func LoadExactBase64[T ~[KeySize]byte](src string) (T, error) {
	slice, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return T{}, err
	}
	if len(slice) != KeySize {
		return T{}, errors.New("hex string does not fit the slice")
	}
	return *(*[KeySize]byte)(slice[:]), nil
}

// XORKeyStream ...
func XORKeyStream(key PresharedKey, nonce []byte, src []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return dst, nil
}

// GenerateSpaPubKeyMD5 spa pubkey to md5 key
func GenerateSpaPubKeyMD5(pubKey string) (string, error) {
	// NewKey ...
	NewKey := func(b []byte) (Key, error) {
		if len(b) != KeySize {
			return Key{}, fmt.Errorf("NewKey: incorrect key size: %d", len(b))
		}
		var k Key
		copy(k[:], b)
		return k, nil
	}

	// ParseKey ...
	ParseKey := func(s string) (Key, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return Key{}, fmt.Errorf("ParseKey:%s failed to parse base64-encoded key: %v", s, err)
		}

		return NewKey(b)
	}

	// HashMD5 ...
	HashMD5 := func(data []byte) string {
		h := md5.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	// HashShortMD5 ...
	HashShortMD5 := func(data []byte) string {
		return HashMD5(data)[8:24]
	}

	// base64 to [32]byte
	cPub, err := ParseKey(pubKey)
	if err != nil {
		return "", err
	}

	// pub [32]byte to md5 Hex string, cut short [8:24]
	cMd5 := HashShortMD5(cPub[:])

	// string to []byte to Hex
	pubmd5 := hex.EncodeToString([]byte(cMd5))
	return pubmd5, nil
}
