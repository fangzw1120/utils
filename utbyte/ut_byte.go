package utbyte

import (
	"encoding/hex"
)

//SliceDecToHex []byte{1, 0, 0, 0, 127, 241, 185, 200, 24, 88, 185, 46, 39, 171, 162, 84, 176, 219, 201, 9}
//to []string{01, 00, 00, 00, 7f, f1, b9, c8, 18, 58, b9, 2e, 27, ab, a2, 54, b0, db, c9}
func SliceDecToHex(data []byte) []string {
	encodedString := hex.EncodeToString(data)
	res := make([]string, 0)
	for i := 0; i < len(encodedString)-3; i = i + 2 {
		res = append(res, encodedString[i:i+2])
	}
	return res
}
