package ioarole

import (
	"fmt"
	"strings"
)

type RoleConfig struct {
	Role          string
	Mid           string
	RootProxyAddr string
}
type (
	clientConfig struct {
		Server clientConfigServer `toml:"server"`
	}
	clientConfigServer struct {
		SrvMode                       string `toml:"srv_mode"`
		SrvHttps                      bool   `toml:"srv_https"`
		MasterControlServer           string `toml:"master_control_server"`
		CentrifugeApi                 string `toml:"centrifuge_api"`
		CentrifugeSecret              string `toml:"centrifuge_hmacSecret"`
		MasterSrv                     string `toml:"master_srv"`
		ConnTcpIpPort                 string `toml:"master_conn_sc_ipport"`
		EncryptSwitch                 int    `toml:"conn_sc_encrypt_switch"`
		SvrMid                        string `toml:"srv_mid"`
		SrvName                       string `toml:"srv_name"`
		NgnCentrifugoIpportRpcxClient string `toml:"ngn_centrifugo_ipport_rpcx_client"`
		SpaAddr                       string `toml:"ngn_spa_http_ipport_server"`      //http服务地址，交换密钥接口
		ClientLoginIpportRpcxClient   string `toml:"client_login_ipport_rpcx_client"` //clientlogin rpcx服务地址，大票校验
		MasterControlProxy            string `toml:"master_control_proxy"`
		LocalGatewayProxyPort         string `toml:"local_gateway_proxy_port"`
	}
)

const (
	ControlSrvMode = "1"
)

var (
	clientServer clientConfig
)

func GetRole() *RoleConfig {
	// note srvMode = 1 一定是root，但是不确定是单机还是多机，是否还有smartgate角色
	// note srvMode = 2 一定是多机环境下的网关角色
	// 总控可能是root等7角色在一台机器，也可能是7角色分开，如果tag是all，就一定包括root等7角色还有smartgate
	// 1总控，单机  2网关
	cfg := &RoleConfig{}
	cfg.Role = clientServer.Server.SrvMode
	cfg.Mid = clientServer.Server.SvrMid

	// 指向总控27900 地址，如果是root角色，指向0000:27900，如果是网关，指向n台root的27900，可能是内网ip，可能是域名
	masterControlServer := clientServer.Server.MasterControlServer

	// 如果总控地址配了多个，那就用本机的地址进行转发
	split := strings.Split(clientServer.Server.MasterControlServer, ",")
	if len(split) > 1 {
		// 使用本地27901转发，依赖后台系统的通道转发到root角色
		masterControlServer = "http://127.0.0.1:27901"
	}
	// 看看是否存在总控转发代理，暂未清楚是地址还是端口
	if clientServer.Server.MasterControlProxy != "" {
		// 转发代理存在，则使用本地LocalGatewayProxyPort转发
		masterControlServer = fmt.Sprintf("http://127.0.0.1:%s", clientServer.Server.LocalGatewayProxyPort)
	}
	cfg.RootProxyAddr = masterControlServer
	return cfg
}
