package utnet

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fangzw1120/utils/utip"
	"github.com/smallnest/rpcx/log"
	"github.com/vishvananda/netlink"
)

// GetPhysicalNICName 获取默认路由的网卡名称
func GetPhysicalNICName() (string, error) {
	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		if route.Dst == nil {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}
			return link.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("physical NIC not found")
}

// IsAddrReachable ip port 是否dial可达
func IsAddrReachable(ip, port string) bool {
	if _, err := net.DialTimeout("tcp", ip+":"+port, time.Second*5); err != nil {
		log.Errorf("%+v", err)
		return false
	}
	return true
}

// Domain2IP 域名本地解析成ip列表
func Domain2IP(host string) map[string]interface{} {
	ipList := make(map[string]interface{})

	// 解析ip地址
	ns, err := net.LookupHost(host)
	if err != nil {
		log.Errorf("parseDomain2IPNet: %+v", err)
		return ipList
	}

	for _, ipAddr := range ns {
		if utip.IsIPv4(ipAddr) {
			ipList[ipAddr] = true
		}
	}
	log.Debugf("parseDomain2IPNet %+v, parse result %+v, filter result %+v", host, ns, ipList)
	return ipList
}

// GetLocalAddress 获取本机ip地址，内网地址优先
func GetLocalAddress() string {
	ips, err := GetIntranetAddress()
	if err != nil {
		return ""
	}
	if len(ips) > 0 {
		return ips[0]
	} else {
		//没有获取到私网ip地址，开始获取公网ip地址
		publicIps, err := getLocalPublicAddress()
		if err != nil {
			return ""
		}
		if len(publicIps) > 0 {
			return publicIps[0]
		}
	}
	//没有获取到ip地址返回默认的127.0.0.1
	return "127.0.0.1"
}

// GetIntranetAddress 获取到私网ip地址
func GetIntranetAddress() (ips []string, err error) {
	ips = make([]string, 0)

	ifaces, e := net.Interfaces()
	if e != nil {
		return ips, e
	}

	for _, iface := range ifaces {

		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		// ignore docker and warden bridge
		if strings.HasPrefix(
			iface.Name, "docker") || strings.HasPrefix(iface.Name, "w-") || strings.HasPrefix(iface.Name, "virbr") {
			continue
		}

		addrs, e := iface.Addrs()
		if e != nil {
			return ips, e
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if IsPublicAddress(ip) {
				continue
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			ipStr := ip.String()
			if IsIntranetAddress(ipStr) {
				ips = append(ips, ipStr)
			}
		}
	}
	return ips, nil
}

// IsIntranetAddress 判断是否私网ip地址
func IsIntranetAddress(ipStr string) bool {
	if strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}

	if strings.HasPrefix(ipStr, "172.") {
		// 172.16.0.0-172.31.255.255
		arr := strings.Split(ipStr, ".")
		if len(arr) != 4 {
			return false
		}

		second, err := strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			return false
		}

		if second >= 16 && second <= 31 {
			return true
		}
	}
	return true
}

// IsPublicAddress 判断是否公网ip地址
func IsPublicAddress(IP net.IP) bool {
	if IP == nil {
		return false
	}
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] <= 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 171:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}

// getLocalPublicAddress 获取公网ip地址
func getLocalPublicAddress() (ips []string, err error) {
	ips = make([]string, 0)

	ifaces, e := net.Interfaces()
	if e != nil {
		return ips, e
	}

	for _, iface := range ifaces {

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		//过滤docker、w-、virbr开头的网卡信息
		if strings.HasPrefix(
			iface.Name, "docker") || strings.HasPrefix(iface.Name, "w-") || strings.HasPrefix(iface.Name, "virbr") {
			continue
		}

		addrs, e := iface.Addrs()
		if e != nil {
			return ips, e
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			ipStr := ip.String()

			ips = append(ips, ipStr)
		}
	}
	return ips, nil
}

// IPNetToCidr IPNet to cidr string
func IPNetToCidr(ipNet net.IPNet) string {
	if ipNet.IP == nil {
		return ""
	}
	res := ipNet.IP.String()
	if res == "" {
		return res
	}
	res += IpMaskToCidr(ipNet.Mask)
	return res
}

// CidrToIPNet cidr to IPNet, last byte of IP is not 0
func CidrToIPNet(cidr string) *net.IPNet {
	ip, subnet, err := net.ParseCIDR(cidr)
	if ip == nil || err != nil {
		return nil
	}
	res := &net.IPNet{
		IP:   ip,
		Mask: subnet.Mask,
	}
	return res
}

// IpMaskToCidr IPMask to string "/24" or "/64" or "/128"
func IpMaskToCidr(ipMask net.IPMask) string {
	ones, _ := ipMask.Size()
	return "/" + strconv.Itoa(ones)
}

// IPv4ToMask 255.255.255.255 to IPMask
func IPv4ToMask(s string) net.IPMask {
	mask := net.ParseIP(s).To4()
	if mask == nil {
		return nil
	}
	return net.IPv4Mask(mask[0], mask[1], mask[2], mask[3])
}

// IPv6OnesToMask "128" or "64" to IPMask
func IPv6OnesToMask(s string) net.IPMask {
	i, err := strconv.Atoi(s)
	if err != nil {
		return net.IPMask{}
	}
	if i < 0 || i > 128 {
		return net.IPMask{}
	}
	return net.CIDRMask(i, 128)
}

// IPv4ToInt ipv4 to int64
func IPv4ToInt(ip net.IP) int64 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	ret := big.NewInt(0)
	ret.SetBytes(ipv4)
	return ret.Int64()
}

// IntToIPv4 int64 to ipv4
func IntToIPv4(ip int64) net.IP {
	newIPStr := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	return net.ParseIP(newIPStr)
}

//func FromNullableTimestampToTime(nt *pb.NullableTimestamp) time.Time {
//	if nt.IsNull {
//		return time.Time{}
//	}
//	t := time.Unix(nt.Timestamp.Seconds, int64(nt.Timestamp.Nanos))
//	return t
//}
//
//func FromNullableTimestamp(nt *pb.NullableTimestamp) sql.NullTime {
//	if nt.IsNull {
//		return sql.NullTime{Valid: false}
//	}
//	t := time.Unix(nt.Timestamp.Seconds, int64(nt.Timestamp.Nanos))
//	return sql.NullTime{Time: t, Valid: true}
//}
