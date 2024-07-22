package utip

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/smallnest/rpcx/log"
)

// ValidatePort 验证端口是否合法
func ValidatePort(port string) bool {
	// 尝试将端口号转换为整数
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}

	// 确保端口号在有效范围内
	if portNum < 1 || portNum > 65535 {
		return false
	}
	return true
}

// IsIPv4 是否是ipv4字符串
func IsIPv4(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return true
}

// IsIPv6 是否是合法的v6地址
func IsIPv6(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip.To4() == nil && ip.To16() != nil {
		return true
	}
	return false
}

// IsIPCidr ...
// @Description: 是否cidr字符串，支持ipv4 ipv6
func IsIPCidr(ipAddr string) bool {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return false
	}
	if ip == nil {
		return false
	}
	return true
}

// IsIPv4Cidr 是否ipv4 cidr字符串
func IsIPv4Cidr(ip string) bool {
	_, _, err := ParseIPv4CIDR(ip)
	if err != nil {
		return false
	}
	return true
}

// IsIPv6Cidr 是否ipv6 cidr字符串
func IsIPv6Cidr(ip string) bool {
	_, _, err := ParseIPv6CIDR(ip)
	if err != nil {
		return false
	}
	return true
}

// ParseIPv6CIDR 解析ipv6 cidr
func ParseIPv6CIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	if ip.To4() != nil || ip.To16() == nil {
		return nil, nil, fmt.Errorf("Invalid IPv6 CIDR: %s", cidr)
	}
	return ip, ipNet, nil
}

// ParseIPv4CIDR 解析ipv4 cidr
func ParseIPv4CIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	if ip.To4() == nil {
		return nil, nil, fmt.Errorf("Invalid IPv4 CIDR: %s", cidr)
	}
	return ip, ipNet, nil
}

// IsSameIP 两个IP地址是否一致
func IsSameIP(ip1, ip2 string) bool {
	ip1Addr, _, err := net.ParseCIDR(ip1)
	if err != nil {
		return false
	}
	if ip1Addr == nil {
		return false
	}

	ip2Addr, _, err := net.ParseCIDR(ip2)
	if err != nil {
		return false
	}
	if ip2Addr == nil {
		return false
	}
	return ip1Addr.Equal(ip2Addr)
}

// Intersect 判断两个网段是否相交
func Intersect(n1, n2 *net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

// ParseIPRedefine same function with net.ParseIP, but less memory
func ParseIPRedefine(ip string) net.IP {
	tIP, _ := ParseIPv4(ip)
	return net.IPv4(tIP.As4()[0], tIP.As4()[1], tIP.As4()[2], tIP.As4()[3])
}

// IPToInt64 ipv4 to int64
func IPToInt64(ip net.IP) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(ip.To4())
	return ret.Int64()
}

// Int64ToIP int64 to ipv4
func Int64ToIP(ip int64) net.IP {
	newIPStr := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	return net.ParseIP(newIPStr)
}

// MaskToIPv4 ipMask to 255.255.255.255
func MaskToIPv4(ipMask net.IPMask) string {
	ones, sizes := ipMask.Size()

	mask := (0xFFFFFFFF << (sizes - ones)) & 0xFFFFFFFF //24 is the netmask
	var dmask uint64
	dmask = 32
	localmask := make([]string, 0, 4)
	for i := 1; i <= 4; i++ {
		tmp := uint64(mask >> (dmask - 8) & 0xFF)
		localmask = append(localmask, strconv.FormatUint(tmp, 10))
		dmask -= 8
	}
	return strings.Join(localmask, ".")
}

// IPv4ToMask 255.255.255.255 to IPMask
func IPv4ToMask(s string) net.IPMask {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	mask := ip.To4()
	if mask == nil {
		return nil
	}
	return net.IPv4Mask(mask[0], mask[1], mask[2], mask[3])
}

// IsPublicIP ipv4地址是否是公网IP
func IsPublicIP(ipCIDR string) (bool, error) {
	IP, _, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return false, err
	}
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false, nil
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false, nil
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false, nil
		case ip4[0] == 192 && ip4[1] == 168:
			return false, nil
		default:
			return true, nil
		}
	}
	return false, nil
}

// GetBroadcastIP ipv4 获取该网段广播地址
func GetBroadcastIP(subnetCidr string) net.IP {
	// 解析CIDR字符串
	ip, ipnet, err := net.ParseCIDR(subnetCidr)
	if err != nil {
		log.Errorf("%+v", err)
		return nil
	}
	ip = ip.To4()

	// 计算广播地址
	mask := ipnet.Mask
	broadcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		broadcast[i] = ip[i] | (^mask[i])
	}
	return broadcast
}

func GetFirstIP(subnetCidr string) net.IP {
	// 解析CIDR字符串
	ip, ipnet, err := net.ParseCIDR(subnetCidr)
	if err != nil {
		log.Errorf("%+v", err)
		return nil
	}
	ip = ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	ip[len(ip)-1] = 1
	return ip
}

// GetSpecialIPsV1 ...
func GetSpecialIPsV1(cidr string, isV6 bool) []string {
	ips := make([]string, 0)

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ips
	}

	// 对于 IPv4，添加网络地址和广播地址
	if !isV6 {
		// 确保是 IPv4 地址
		if !IsIPv4(ip.String()) {
			log.Errorf("GetSpecialIPs not ipv4 %+v", cidr)
			return ips
		}

		ipv4 := ip.To4()
		// 计算网络起始地址和结束地址
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		start := binary.BigEndian.Uint32(ipv4) & mask
		finish := (start | ^mask)

		// 遍历每个子网
		for i := start; i <= finish; i += 256 { // 每个子网的步长是256（即一个字节的范围）
			// 网络地址
			netIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(netIP, i)
			ips = append(ips, netIP.String())

			// 第一个主机地址
			firstHostIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(firstHostIP, i+1)
			ips = append(ips, firstHostIP.String())

			// 广播地址
			broadcastIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(broadcastIP, i+255)
			ips = append(ips, broadcastIP.String())
		}

	} else {
		// 确保是 IPv6 地址
		if !IsIPv6(ip.String()) {
			log.Errorf("GetSpecialIPs not IPv6 %+v", cidr)
			return ips
		}

		ipv6 := ip.To16()
		// 获取子网的基础地址（即后 64 位全为0）
		base := ipv6.Mask(ipNet.Mask)
		ips = append(ips, base.String())

		// 获取第一个地址（即后 64 位中只有最低位为1）
		first := make(net.IP, len(base))
		copy(first, base)
		first[15] = 1 // 设置最后一个字节的最低位为1

		ips = append(ips, first.String())
	}

	return ips
}

// GetSpecialIPs 获取IPv4网段，最后一位为0、1、255等特殊地址列表
func GetSpecialIPs(cidr string) []string {
	ips := make([]string, 0)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ips
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip) && ip != nil; inc(ip) {
		lastByte := ip[len(ip)-1]
		if lastByte == 0 || lastByte == 1 || lastByte == 255 {
			ips = append(ips, ip.String())
		}
	}

	return ips
}

// inc IP自增
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPMask2CIDR 255.255.255.0 to /24
func IPMask2CIDR(mask string) string {
	ip := net.ParseIP(mask)
	if ip == nil {
		return "/"
	}
	addr := ip.To4()
	if addr == nil {
		return "/"
	}
	sz, _ := net.IPv4Mask(addr[0], addr[1], addr[2], addr[3]).Size()
	res := "/" + strconv.Itoa(sz)
	return res
}

// IPNetToCidr IPNet to xx.xx.xx.xx/xx
func IPNetToCidr(ipNet net.IPNet) string {
	res := ipNet.IP.String()
	if res == "" {
		return res
	}
	res += IPMask2CIDR(MaskToIPv4(ipNet.Mask))
	return res
}

// CidrToIPNet IPNet to xx.xx.xx.xx/xx, reverse
func CidrToIPNet(cidr string) *net.IPNet {
	ip, subnet, err := net.ParseCIDR(cidr)
	if ip == nil || err != nil {
		return &net.IPNet{}
	}
	res := &net.IPNet{
		IP:   ip,
		Mask: subnet.Mask,
	}
	return res
}

// IsSameSubnet 两个cidr字符串，代表两个网段，判断两个网段是否一致
func IsSameSubnet(ip1, ip2 string) bool {
	ip1Addr, ip1Net, err := net.ParseCIDR(ip1)
	if err != nil {
		return false
	}

	ip2Addr, ip2Net, err := net.ParseCIDR(ip2)
	if err != nil {
		return false
	}

	if ip1Net.Contains(ip2Addr) && ip2Net.Contains(ip1Addr) && ip1Net.Mask.String() == ip2Net.Mask.String() {
		return true
	}
	return false
}

// IPToUint32 类型转换
func IPToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return (uint32(ipv4[0]) << 24) | (uint32(ipv4[1]) << 16) | (uint32(ipv4[2]) << 8) | uint32(ipv4[3])
}

// Uint32ToIP 类型转换
func Uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
