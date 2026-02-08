package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/pazakharov/goproxy/services"
	"github.com/pazakharov/goproxy/utils"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app     *kingpin.Application
	service *services.ServiceItem
)

func initConfig() (err error) {
	//keygen
	if len(os.Args) > 1 {
		if os.Args[1] == "keygen" {
			utils.Keygen()
			os.Exit(0)
		}
	}
	args := services.Args{}
	//define  args
	tcpArgs := services.TCPArgs{}
	httpArgs := services.HTTPArgs{}
	autoArgs := services.HTTPArgs{} // reuses HTTPArgs for auto-detect mode
	tunnelServerArgs := services.TunnelServerArgs{}
	tunnelClientArgs := services.TunnelClientArgs{}
	tunnelBridgeArgs := services.TunnelBridgeArgs{}
	udpArgs := services.UDPArgs{}

	//build srvice args
	app = kingpin.New("proxy", "happy with proxy")
	app.Author("snail").Version(APP_VERSION)
	args.Parent = app.Flag("parent", "parent address, such as: \"23.32.32.19:28008\"").Default("").Short('P').String()
	args.Local = app.Flag("local", "local ip:port to listen").Short('p').Default(":33080").String()
	certTLS := app.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	keyTLS := app.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()

	//########http#########
	http := app.Command("http", "proxy on http mode")
	httpArgs.LocalType = http.Flag("local-type", "parent protocol type <tls|tcp>").Default("tcp").Short('t').Enum("tls", "tcp")
	httpArgs.ParentType = http.Flag("parent-type", "parent protocol type <tls|tcp>").Short('T').Enum("tls", "tcp")
	httpArgs.Always = http.Flag("always", "always use parent proxy").Default("false").Bool()
	httpArgs.Timeout = http.Flag("timeout", "tcp timeout milliseconds when connect to real server or parent proxy").Default("2000").Int()
	httpArgs.HTTPTimeout = http.Flag("http-timeout", "check domain if blocked , http request timeout milliseconds when connect to host").Default("3000").Int()
	httpArgs.Interval = http.Flag("interval", "check domain if blocked every interval seconds").Default("10").Int()
	httpArgs.Blocked = http.Flag("blocked", "blocked domain file , one domain each line").Default("blocked").Short('b').String()
	httpArgs.Direct = http.Flag("direct", "direct domain file , one domain each line").Default("direct").Short('d').String()
	httpArgs.AuthFile = http.Flag("auth-file", "http basic auth file,\"username:password\" each line in file").Short('F').String()
	httpArgs.Auth = http.Flag("auth", "http basic auth username and password, mutiple user repeat -a ,such as: -a user1:pass1 -a user2:pass2").Short('a').Strings()
	httpArgs.AuthURL = http.Flag("auth-url", "external http auth api url, returns 204 on success").String()
	httpArgs.AuthTimeout = http.Flag("auth-timeout", "auth api request timeout milliseconds").Default("3000").Int()
	httpArgs.AuthCacheTTL = http.Flag("auth-cache-ttl", "auth result cache TTL seconds, 0 to disable").Default("60").Int()
	httpArgs.PoolSize = http.Flag("pool-size", "conn pool size , which connect to parent proxy, zero: means turn off pool").Short('L').Default("20").Int()
	httpArgs.CheckParentInterval = http.Flag("check-parent-interval", "check if proxy is okay every interval seconds,zero: means no check").Short('I').Default("3").Int()
	httpArgs.Debug = http.Flag("debug", "enable debug logging").Default("false").Bool()
	httpArgs.MaxConns = http.Flag("max-conns", "maximum concurrent connections, 0 = unlimited").Default("10000").Int()
	httpArgs.TrafficURL = http.Flag("traffic-url", "traffic reporting HTTP endpoint URL").Default("").String()
	httpArgs.TrafficMode = http.Flag("traffic-mode", "traffic reporting mode: normal|fast").Default("normal").Enum("normal", "fast")
	httpArgs.TrafficInterval = http.Flag("traffic-interval", "traffic reporting interval in seconds for fast mode").Default("5").Int()
	httpArgs.FastGlobal = http.Flag("fast-global", "use single global reporter for fast mode (POST JSON)").Default("false").Bool()

	//########auto#########
	auto := app.Command("auto", "proxy with auto-detect (HTTP/SOCKS5 on same port)")
	autoArgs.LocalType = auto.Flag("local-type", "parent protocol type <tls|tcp>").Default("tcp").Short('t').Enum("tls", "tcp")
	autoArgs.ParentType = auto.Flag("parent-type", "parent protocol type <tls|tcp>").Short('T').Enum("tls", "tcp")
	autoArgs.Always = auto.Flag("always", "always use parent proxy").Default("false").Bool()
	autoArgs.Timeout = auto.Flag("timeout", "tcp timeout milliseconds when connect to real server or parent proxy").Default("2000").Int()
	autoArgs.HTTPTimeout = auto.Flag("http-timeout", "check domain if blocked , http request timeout milliseconds when connect to host").Default("3000").Int()
	autoArgs.Interval = auto.Flag("interval", "check domain if blocked every interval seconds").Default("10").Int()
	autoArgs.Blocked = auto.Flag("blocked", "blocked domain file , one domain each line").Default("blocked").Short('b').String()
	autoArgs.Direct = auto.Flag("direct", "direct domain file , one domain each line").Default("direct").Short('d').String()
	autoArgs.AuthFile = auto.Flag("auth-file", "http basic auth file,\"username:password\" each line in file").Short('F').String()
	autoArgs.Auth = auto.Flag("auth", "http basic auth username and password, mutiple user repeat -a ,such as: -a user1:pass1 -a user2:pass2").Short('a').Strings()
	autoArgs.AuthURL = auto.Flag("auth-url", "external http auth api url, returns 204 on success").String()
	autoArgs.AuthTimeout = auto.Flag("auth-timeout", "auth api request timeout milliseconds").Default("3000").Int()
	autoArgs.AuthCacheTTL = auto.Flag("auth-cache-ttl", "auth result cache TTL seconds, 0 to disable").Default("60").Int()
	autoArgs.PoolSize = auto.Flag("pool-size", "conn pool size , which connect to parent proxy, zero: means turn off pool").Short('L').Default("20").Int()
	autoArgs.CheckParentInterval = auto.Flag("check-parent-interval", "check if proxy is okay every interval seconds,zero: means no check").Short('I').Default("3").Int()
	autoArgs.Debug = auto.Flag("debug", "enable debug logging").Default("false").Bool()
	autoArgs.MaxConns = auto.Flag("max-conns", "maximum concurrent connections, 0 = unlimited").Default("10000").Int()
	autoArgs.TrafficURL = auto.Flag("traffic-url", "traffic reporting HTTP endpoint URL").Default("").String()
	autoArgs.TrafficMode = auto.Flag("traffic-mode", "traffic reporting mode: normal|fast").Default("normal").Enum("normal", "fast")
	autoArgs.TrafficInterval = auto.Flag("traffic-interval", "traffic reporting interval in seconds for fast mode").Default("5").Int()
	autoArgs.FastGlobal = auto.Flag("fast-global", "use single global reporter for fast mode (POST JSON)").Default("false").Bool()

	//########tcp#########
	tcp := app.Command("tcp", "proxy on tcp mode")
	tcpArgs.Timeout = tcp.Flag("timeout", "tcp timeout milliseconds when connect to real server or parent proxy").Short('t').Default("2000").Int()
	tcpArgs.ParentType = tcp.Flag("parent-type", "parent protocol type <tls|tcp|udp>").Short('T').Enum("tls", "tcp", "udp")
	tcpArgs.IsTLS = tcp.Flag("tls", "proxy on tls mode").Default("false").Bool()
	tcpArgs.PoolSize = tcp.Flag("pool-size", "conn pool size , which connect to parent proxy, zero: means turn off pool").Short('L').Default("20").Int()
	tcpArgs.CheckParentInterval = tcp.Flag("check-parent-interval", "check if proxy is okay every interval seconds,zero: means no check").Short('I').Default("3").Int()
	tcpArgs.TrafficURL = tcp.Flag("traffic-url", "traffic reporting HTTP endpoint URL").Default("").String()
	tcpArgs.TrafficMode = tcp.Flag("traffic-mode", "traffic reporting mode: normal|fast").Default("normal").Enum("normal", "fast")
	tcpArgs.TrafficInterval = tcp.Flag("traffic-interval", "traffic reporting interval in seconds for fast mode").Default("5").Int()
	tcpArgs.FastGlobal = tcp.Flag("fast-global", "use single global reporter for fast mode (POST JSON)").Default("false").Bool()

	//########udp#########
	udp := app.Command("udp", "proxy on udp mode")
	udpArgs.Timeout = udp.Flag("timeout", "tcp timeout milliseconds when connect to parent proxy").Short('t').Default("2000").Int()
	udpArgs.ParentType = udp.Flag("parent-type", "parent protocol type <tls|tcp|udp>").Short('T').Enum("tls", "tcp", "udp")
	udpArgs.PoolSize = udp.Flag("pool-size", "conn pool size , which connect to parent proxy, zero: means turn off pool").Short('L').Default("20").Int()
	udpArgs.CheckParentInterval = udp.Flag("check-parent-interval", "check if proxy is okay every interval seconds,zero: means no check").Short('I').Default("3").Int()
	udpArgs.TrafficURL = udp.Flag("traffic-url", "traffic reporting HTTP endpoint URL").Default("").String()
	udpArgs.TrafficMode = udp.Flag("traffic-mode", "traffic reporting mode: normal|fast").Default("normal").Enum("normal", "fast")
	udpArgs.TrafficInterval = udp.Flag("traffic-interval", "traffic reporting interval in seconds for fast mode").Default("5").Int()
	udpArgs.FastGlobal = udp.Flag("fast-global", "use single global reporter for fast mode (POST JSON)").Default("false").Bool()

	//########tunnel-server#########
	tunnelServer := app.Command("tserver", "proxy on tunnel server mode")
	tunnelServerArgs.Timeout = tunnelServer.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()
	tunnelServerArgs.IsUDP = tunnelServer.Flag("udp", "proxy on udp tunnel server mode").Default("false").Bool()
	tunnelServerArgs.Key = tunnelServer.Flag("k", "key same with client").Default("default").String()

	//########tunnel-client#########
	tunnelClient := app.Command("tclient", "proxy on tunnel client mode")
	tunnelClientArgs.Timeout = tunnelClient.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()
	tunnelClientArgs.IsUDP = tunnelClient.Flag("udp", "proxy on udp tunnel client mode").Default("false").Bool()
	tunnelClientArgs.Key = tunnelClient.Flag("k", "key same with server").Default("default").String()

	//########tunnel-bridge#########
	tunnelBridge := app.Command("tbridge", "proxy on tunnel bridge mode")
	tunnelBridgeArgs.Timeout = tunnelBridge.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *certTLS != "" && *keyTLS != "" {
		args.CertBytes, args.KeyBytes = tlsBytes(*certTLS, *keyTLS)
	}

	//common args
	httpArgs.Args = args
	autoArgs.Args = args
	tcpArgs.Args = args
	udpArgs.Args = args
	tunnelBridgeArgs.Args = args
	tunnelClientArgs.Args = args
	tunnelServerArgs.Args = args

	poster()
	//regist services and run service
	serviceName := kingpin.MustParse(app.Parse(os.Args[1:]))
	services.Regist("http", services.NewHTTP(), httpArgs)
	services.Regist("auto", services.NewAuto(), autoArgs)
	services.Regist("tcp", services.NewTCP(), tcpArgs)
	services.Regist("udp", services.NewUDP(), udpArgs)
	services.Regist("tserver", services.NewTunnelServer(), tunnelServerArgs)
	services.Regist("tclient", services.NewTunnelClient(), tunnelClientArgs)
	services.Regist("tbridge", services.NewTunnelBridge(), tunnelBridgeArgs)
	service, err = services.Run(serviceName)
	if err != nil {
		log.Fatalf("run service [%s] fail, ERR:%s", service, err)
	}
	return
}

func poster() {
	fmt.Printf(`
		########  ########   #######  ##     ## ##    ## 
		##     ## ##     ## ##     ##  ##   ##   ##  ##  
		##     ## ##     ## ##     ##   ## ##     ####   
		########  ########  ##     ##    ###       ##    
		##        ##   ##   ##     ##   ## ##      ##    
		##        ##    ##  ##     ##  ##   ##     ##    
		##        ##     ##  #######  ##     ##    ##    
		
		v%s`+" by snail , blog : http://www.host900.com/\n\n", APP_VERSION)
}
func tlsBytes(cert, key string) (certBytes, keyBytes []byte) {
	certBytes, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Fatalf("err : %s", err)
		return
	}
	keyBytes, err = ioutil.ReadFile(key)
	if err != nil {
		log.Fatalf("err : %s", err)
		return
	}
	return
}
