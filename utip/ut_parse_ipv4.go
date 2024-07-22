package utip

import "errors"

// uint128 ...
type uint128 struct {
	hi uint64
	lo uint64
}

// Addr ...
// @Description:
//
type Addr struct {
	addr uint128
}

const digits = "0123456789abcdef"

// As4 ...
func (ip Addr) As4() (a4 [4]byte) {
	bePutUint32(a4[:], uint32(ip.addr.lo))
	return a4
}

// String ...
func (ip Addr) String() string {
	return ip.string4()
}

func (ip Addr) string4() string {
	const max = len("255.255.255.255")
	ret := make([]byte, 0, max)
	ret = ip.appendTo4(ret)
	return string(ret)
}

func (ip Addr) appendTo4(ret []byte) []byte {
	ret = appendDecimal(ret, ip.v4(0))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(1))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(2))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(3))
	return ret
}

func (ip Addr) v4(i uint8) uint8 {
	return uint8(ip.addr.lo >> ((3 - i) * 8))
}

func appendDecimal(b []byte, x uint8) []byte {
	// Using this function rather than strconv.AppendUint makes IPv4
	// string building 2x faster.

	if x >= 100 {
		b = append(b, digits[x/100])
	}
	if x >= 10 {
		b = append(b, digits[x/10%10])
	}
	return append(b, digits[x%10])
}

func bePutUint32(b []byte, v uint32) {
	_ = b[3] // early bounds check to guarantee safety of writes below
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// ParseIPv4 ...
// @Description: use less mem, copy function from tIP, _ := netip.ParseAddr(pcCol.ip), net.ParseIP cost too much
// @param s
// @return ip
// @return err
//
func ParseIPv4(s string) (ip Addr, err error) {
	var fields [4]uint8
	var val, pos int
	var digLen int // number of digits in current octet
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if digLen == 1 && val == 0 {
				return Addr{}, errors.New("IPv4 field has octet with leading zero")
			}
			val = val*10 + int(s[i]) - '0'
			digLen++
			if val > 255 {
				return Addr{}, errors.New("IPv4 field has value >255")
			}
		} else if s[i] == '.' {
			// .1.2.3
			// 1.2.3.
			// 1..2.3
			if i == 0 || i == len(s)-1 || s[i-1] == '.' {
				return Addr{}, errors.New("IPv4 field must have at least one digit")
			}
			// 1.2.3.4.5
			if pos == 3 {
				return Addr{}, errors.New("IPv4 address too long")
			}
			fields[pos] = uint8(val)
			pos++
			val = 0
			digLen = 0
		} else {
			return Addr{}, errors.New("unexpected character")
		}
	}
	if pos < 3 {
		return Addr{}, errors.New("IPv4 address too short")
	}
	fields[3] = uint8(val)
	return addrFrom4(fields), nil
}

func addrFrom4(addr [4]byte) Addr {
	return Addr{
		addr: uint128{0,
			0xffff00000000 | uint64(addr[0])<<24 | uint64(addr[1])<<16 | uint64(addr[2])<<8 | uint64(addr[3])},
	}
}
