/*
本程序目标检验 gws.txt文件
  检查cert是否为google.com
  根据tls时间，重新排序生成check.txt文件
google gws 特性:
   tls 中servername 不填写时，发出报文中servername为ip, 此时服务端返回了其所有支持的cert
   tls 中servername 填写为google时，发出报文中为填写值，此时服务端反而返回了google.com相关的cert，与上不同
   当有servername且InsecureSkipVerify为fale时，如证书不对，则tls连接直接会报错，下文不可再取header等
功能规划:
   输入：支持对myscan的三种结果文件作为输入文件，    gws(gws-sort),unknow,other, 注意尾部servername带多空格的处理
   输出: check-gws,           check-fail,                      check-unknow
    	cert  原cert,gws     原cert,原svr                      原cert,新svr
	    tls   成功               失败                               成功
	    情况   ok        cert错,连接错,tlshnad, RespHead 其他错  status错,gws错
	    time  new             0    -1    -2     -3       -4        new
	   比对串         "certificate is valid for"    0
	                 "ConnectEx tcp: i/o timeout" -1
					 "TLS handshake timeout"      -2
	                 "timeout awaiting response headers" -3
*/

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	//本程序为check程序，以下参数均放大一些
	//重要连接参数，单位秒,以下1，5，4参数已很苛刻，可以再放大些
	MAX_WORK_COUNT                          = 100 //实测本机400以下，否则断流无输出或各Tls时间加长
	MAX_ResponseHeaderTimeout time.Duration = 2   //可优化为1以上，表示服务器回应速度，发送请求后开始计时，因此它指的是等待响应的超时时间
	MAX_TLSHandshakeTimeout   time.Duration = 6   //可优化为4以上,表示TLS握手超时时间
	MAX_DialTimeout           time.Duration = 5   //可优化为4以上,表示连接超时时间，重要参数，过低会无结果

)

var ( //默认数值都是0

	//MY_TIMEOUT_CONNECT time.Duration = 4 //原数值5太慢了,该数值实际决定了扫描速率,暂停使用，原因原来的是二次连接，现一次连接

	syncWaitGroup sync.WaitGroup //同步等待组，各go程等待

	nCountScan int32 //已扫ip总数,原子数值
	nCountGws  int32 //获得gws总数，原子数值

	nTotalIp int //总数量

	chIp           = make(chan uint32, MAX_WORK_COUNT)     //ip信道，供应各go程ip
	chQuitRecvWalk = make(chan int, 1)                     //退出信道，用于recvWalk退出
	chtagIpGws     = make(chan tagIpRecod, MAX_WORK_COUNT) //接收信道，gws记录
	chtagIpFail    = make(chan tagIpRecod, MAX_WORK_COUNT) //接收信道，非gws记录
	chtagIpUnknow  = make(chan tagIpRecod, MAX_WORK_COUNT) //接收信道，可疑gws记录

	stagIpGws stagIpRecords //[]tagIpRecod //slice gws结果, 需要这么定义，下文才能sort
	//stagIpOther  []tagIpRecod  //slice 非gws结果
	//stagIpUnknow []tagIpRecod  //slice 可疑gws结果
	nCountIpFail   int //递增变量，不必原子,不再记录slice,
	nCountIpUnknow int //递增变量，不必原子,不再记录slice,

	sdwIp []uint32 //所有待扫ip的slice,uint32类型，减少string内存占用

	timeStartScan time.Time //开始扫描的时间，用于计算耗时和速度

	strTimeNow string
	strPath    string //当前exe文件路径，全部结果都存储在此路径下，不管从何处拖拽的源文件
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			//MaxIdleConnsPerHost: 1, //默认为2
			ResponseHeaderTimeout: MAX_ResponseHeaderTimeout * time.Second,
			//DisableKeepAlives:     true,
			TLSHandshakeTimeout: MAX_TLSHandshakeTimeout * time.Second,

			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,            //要求校验证书
				ServerName:         "appspot.com",    //"google.com", //校验的域名
				MinVersion:         tls.VersionTLS12, //强制使用tls1.2版本，不允许服务端降级
				//MaxVersion:         tls.VersionTLS12,//不必填写，默认0时选最高版本，当前为1.2
				//PreferServerCipherSuites: true, //待
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					//					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					//					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				},
			},

			Dial: (&net.Dialer{
				Timeout: MAX_DialTimeout * time.Second,
				//KeepAlive: 0, //10 * time.Minute, 0表示禁止
			}).Dial,
		},
	}
)

func main() {
	oldmain()
	fmt.Scanln()
}

func oldmain() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	if len(os.Args) != 2 { //即要求两形参，与c中argc相似，无参数时len为1
		fmt.Println("MyCheck [gws-sort.txt]")
		return
	}
	strCheckFileName := os.Args[1]

	if err := parseCheckFile(strCheckFileName); err != nil {
		fmt.Println("[-] 解析出错,", err)
		return
	}
	shuffle(&sdwIp) //统一随机排序

	nTotalIp = len(sdwIp)
	fmt.Println("[M] 检查ip数量:", nTotalIp)
	fmt.Println("[M] 当前go程数:", MAX_WORK_COUNT)

	//初始化时间串，为下文文件名准备
	t := time.Now()
	strTimeNow = fmt.Sprintf("%02d%02d-%02d%02d%02d-check",
		t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	//获取exe文件路径，便于所有输出文件都保存在本目录下，规避go的默认是windows系统文档目录
	strFullName, _ := filepath.Abs(os.Args[0]) //扩展为完整带路径全名
	strMainName := filepath.Base(strFullName)  //短文件名, 例如aaa.txt
	//strExtName := filepath.Ext(strFullName) //取扩展名,例如".txt"
	strPath = strings.TrimSuffix(strFullName, strMainName) //获得了路径

	syncWaitGroup.Add(MAX_WORK_COUNT) //加入多等待,下文等待所有扫描go程退出

	//1个go程，接收结果数据
	go MyRecvWalk()

	//n个go程，扫描, 会阻塞等待给ip
	for i := 0; i < MAX_WORK_COUNT; i++ {
		go MyScanWalk()
	}

	//ctrl+c注册信道
	chCtrlC := make(chan os.Signal, 1)
	signal.Notify(chCtrlC, os.Interrupt)

	fmt.Println("[M] 开始检查......")
	timeStartScan = time.Now()

	//1个go程，信道供给ip，且捕捉ctrl+c信号
	go func() {
		for _, dwIp := range sdwIp {
			select {
			case chIp <- dwIp:
				//留空,仅输入ip
			case <-chCtrlC:
				fmt.Println("[M] 捕捉到Ctrl+C.")
				goto CtrlC
			}
		}
	CtrlC:
		fmt.Println("[M] 通知各go程退出.")
		for i := 0; i < MAX_WORK_COUNT; i++ {
			chIp <- 0
		}
	}()

	fmt.Println("[M] 等待各go程退出......")
	syncWaitGroup.Wait() //等待所有扫描go程的退出信号
	chQuitRecvWalk <- 0  //通知recvWalk退出
	//fmt.Println("[M] 各扫描go程已全部退出.")

	timeUsed := time.Now().Sub(timeStartScan)
	//	fmt.Printf("[M] 扫描结束, GWS总数:%v, 耗时:%v, 速率:%.0f\n",
	//		atomic.LoadInt32(&nCountGws),
	//		timeUsed.String(),
	//		float64(nTotalIp)/timeUsed.Seconds())

	//关闭文件,不含gws-sort（此时还未打开）
	for _, hFile := range hFiles {
		if hFile != nil {
			hFile.Close()
		}
	}

	//不必再用原子，原因此时其他go程已全部退出
	fmt.Printf("[M] 扫描结束, 总数:%v, 耗时:%v, 速率:%.0f\n",
		nCountScan,
		timeUsed.String(),
		float64(nCountScan)/timeUsed.Seconds())

	//fmt.Printf("[M] GWS:%v, 可疑:%v, 其他:%v\n", len(stagIpGws), len(stagIpUnknow), len(stagIpOther))
	fmt.Printf("[M] GWS:%v, 可疑:%v, 其他:%v\n", len(stagIpGws), nCountIpUnknow, nCountIpFail)

	if len(stagIpGws) == 0 {
		return
	}

	//按时间排序
	sort.Sort(&stagIpGws)
	//写排序后文件
	for _, tagOne := range stagIpGws {
		MyWriteFile(&tagOne, TYPE_GWS_SORT)
	}

	if hFiles[TYPE_GWS_SORT] == nil {
		fmt.Println("[-] 保存文件失败,", saveFileName[TYPE_GWS_SORT])
		return
	}

	//扫尾关闭，删除未排序，重命名结果文件
	hFiles[TYPE_GWS_SORT].Close()
	fmt.Println("[M] 排序CHECK-GWS文件成功.")

	//删除未排序的gws文件
	os.Remove(saveFileName[TYPE_GWS])
	//改名结果文件，并带上输入文件的后缀信息
	MyRenameFile(strCheckFileName, saveFileName[TYPE_GWS_SORT])

}

//获取输入文件的后缀，添加为输出文件的后缀，便于反复check时文件名清晰
//例如: 输入  0225-084634-gws-sort-【公司_电信】.txt
//     输出  0225-093635-gws-sort-【公司_电信】.txt
//形参1：strCheckFileName, 输入的check文件名
//形参2：strOldSaveFileNmae, gws-sort的标准名
//结果： 将形参2文件名修改为了举例格式的文件名
func MyRenameFile(strCheckFileName, strOldSaveFileNmae string) {
	ssFalg := []string{"【", "（", "(", "["}
	var strSep string //go会默认初始化为空串
	for _, sep := range ssFalg {
		if strings.Contains(strCheckFileName, sep) { //含有
			strSep = sep
			break
		}
	}
	if strSep == "" { //未找到标志
		return
	}
	ss := strings.Split(strCheckFileName, strSep)
	if len(ss) != 2 {
		return
	}
	strNewName := strings.Replace(strOldSaveFileNmae, ".txt", strSep+ss[1], 1)
	os.Rename(strOldSaveFileNmae, strNewName)
}

const (
	TYPE_GWS = iota //iota定义常数组从0开始递增
	TYPE_UNKNOW
	TYPE_FAIL
	TYPE_GWS_SORT
)

var ( //标志，目的一次性建立文件
	hFiles      [4]*os.File //初始为nil
	bCreateFail [4]bool     //初始为false

	fileSubName = [4]string{
		"gws",
		"unknow",
		"fail",
		"gws-sort",
	}

	saveFileName [4]string
)

//返回：对应类型的文件句柄，当有数据来时才一次性建立文件，如建立失败则不二次建立
func pressFile(nType int) *os.File {
	if nType > TYPE_GWS_SORT { //超界
		return nil
	}
	if bCreateFail[nType] { //曾经建立失败
		return nil
	}
	if hFiles[nType] == nil { //文件句柄为空，则需要首次建立
		var err error
		//一次性生成保存的响应类型的文件名，便于下文使用
		saveFileName[nType] = strPath + strTimeNow + "-" + fileSubName[nType] + ".txt"
		hFiles[nType], err = os.OpenFile(saveFileName[nType], os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil || hFiles[nType] == nil {
			bCreateFail[nType] = true //置标志，避免二次建立失败
			hFiles[nType] = nil
			return nil
		}
	}
	return hFiles[nType]
}

//尝试首次有数据时,一次性建立文件
func MyWriteFile(ptagOne *tagIpRecod, nType int) {
	hFile := pressFile(nType)
	if hFile == nil {
		return
	}
	hFile.WriteString(fmt.Sprintf("%s %s %s %s\r\n", ptagOne.strIp, ptagOne.strTlsTime, ptagOne.strCert, ptagOne.strServer))
}

//go程1个,接收数据
func MyRecvWalk() {
	var tagOne tagIpRecod
	for {
		select {
		case <-chQuitRecvWalk:
			//fmt.Println("[M] MyRecvWalk go程退出.")
			return
		case tagOne = <-chtagIpGws:
			stagIpGws = append(stagIpGws, tagOne)
			atomic.AddInt32(&nCountGws, 1) //原子递增1,下文扫描go程中会原子取用
			MyWriteFile(&tagOne, TYPE_GWS)
			fmt.Println("[+]", tagOne.strIp, tagOne.strTlsTime, tagOne.strCert, tagOne.strServer)
		case tagOne = <-chtagIpFail:
			//stagIpOther = append(stagIpOther, tagOne)
			MyWriteFile(&tagOne, TYPE_FAIL)
			nCountIpFail++
			//fmt.Println("[-]", tagOne.strIp, tagOne.strTlsTime, tagOne.strCert, tagOne.strServer)
		case tagOne = <-chtagIpUnknow:
			//stagIpUnknow = append(stagIpUnknow, tagOne)
			MyWriteFile(&tagOne, TYPE_UNKNOW)
			nCountIpUnknow++
			fmt.Println("[U]", tagOne.strIp, tagOne.strTlsTime, tagOne.strCert, tagOne.strServer)
		}
	}

}

//go程n个，扫描
func MyScanWalk() {

	for dwIp := range chIp {
		if dwIp == 0 {
			syncWaitGroup.Done() //本go程退出，告知一个wait
			break
		}

		MyScanOne(inet_ntosb(dwIp).String())
		nCountNow := atomic.AddInt32(&nCountScan, 1) //原子递增1

		if (nCountNow % 100) == 0 {
			timeUsed := time.Now().Sub(timeStartScan)
			fmt.Printf("***** 已扫描:%d, 进度:%v%%, 耗时:%v, 速率:%.0f, GWS:%v *****\n",
				nCountNow,
				int(nCountNow)*100/nTotalIp,
				timeUsed.String(),
				float64(nCountNow)/timeUsed.Seconds(),
				atomic.LoadInt32(&nCountGws))
		}
	}
}

type tagGoogleCert struct {
	Country      string
	Organization string
	CommonName   string
}

var tagGoCert = []tagGoogleCert{
	{"[US]", "[Google Inc]", "*.appspot.com"},
	{"[US]", "[Google Inc]", "Google Internet Authority G2"},
	{"[US]", "[GeoTrust Inc.]", "GeoTrust Global CA"},
}

func MyScanOne(strIp string) {

	//一次连接,tcp443,省略掉
	//	start_time := time.Now()
	//	c, err := net.DialTimeout("tcp", strIp+":443", MY_TIMEOUT_CONNECT*time.Second) //time.Millisecond*100
	//	if err != nil {
	//		//fmt.Println("[-] DialTimeout err.", err)
	//		return
	//	}
	//	timeConnect := time.Now().Sub(start_time).Seconds() * 1000
	//	c.Close()

	//fmt.Printf("[+] connect %s:443 ok, %.0fms\n", ip, timeConnect)

	//timeConnect := 0.0

	//二次连接,估计是在规避gfw的行为，原因：首连很快，二连慢，估计首连已被gfw本地截获，而二连可能未截获所致
	//tls握手
	startTimeTls := time.Now()
	req, err := http.NewRequest("GET", "https://"+strIp, nil)
	//req, err := http.NewRequest("HEAD", "https://"+strIp, nil)
	resp, err := client.Transport.RoundTrip(req)

	var tagOne tagIpRecod
	tagOne.strIp = strIp

	/*
	      输出: check-gws,       check-fail,                      check-unknow
	       cert  原cert,gws     原cert,原svr                      原cert,新svr
	       tls   成功               失败                               成功
	       情况   ok        cert错,连接错,tlshnad, RespHead 其他错  status错,gws错
	       time  new             0    -1    -2     -3       -4        new
	      比对串         "certificate is valid for"    0
	                    "ConnectEx tcp: i/o timeout" -1
	   				 "TLS handshake timeout"      -2
	                       "timeout awaiting response headers" -3
	*/

	if err != nil {

		//		if strings.Contains(strErr, "certificate is valid for") {
		//			tagOne.strTlsTime = "0_CertErr" //cert错
		//		} else if strings.Contains(strErr, "ConnectEx tcp: i/o timeout") {
		//			tagOne.strTlsTime = "1_Connect" //连接错
		//		} else if strings.Contains(strErr, "TLS handshake timeout") {
		//			tagOne.strTlsTime = "2_TlsHand" //TlsHand超时
		//		} else if strings.Contains(strErr, "timeout awaiting response headers") {
		//			tagOne.strTlsTime = "3_RespHead" //RespHead超时
		//		} else {
		//			tagOne.strTlsTime = "4_OtherErr" //其他错
		//			fmt.Println("[-]", strErr)
		//		}
		strErr := fmt.Sprintf("%v", err)
		switch {
		case strings.Contains(strErr, "ConnectEx tcp: i/o timeout"):
			tagOne.strTlsTime = "1_Connect" //连接错
		case strings.Contains(strErr, "TLS handshake timeout"):
			tagOne.strTlsTime = "2_TlsHand" //TlsHand超时
		case strings.Contains(strErr, "timeout awaiting response headers"):
			tagOne.strTlsTime = "3_RespHead" //RespHead超时
		case strings.Contains(strErr, "certificate is valid for"):
			tagOne.strTlsTime = "0_CertValid" //cert错
		default:
			tagOne.strTlsTime = "4_OtherErr" //其他错
			fmt.Println("[-]", strErr)
		}

		tagOne.strCert = maptagIpOld[strIp].strOldCert
		tagOne.strServer = maptagIpOld[strIp].strOldServer

		chtagIpFail <- tagOne
		return
	}
	timeTls := time.Now().Sub(startTimeTls).Seconds() * 1000 //毫秒
	//defer resp.Body.Close()
	resp.Body.Close() //抓包及实测表明，此处可以直接关闭了，效率点且减少接收流量。不影响下文取信息
	//fmt.Printf("[+] TLSHandshake(1.2) time : %.0fms\n", timeTls)

	//仅仅检查证书名字否是google
	//	bCert := false
	//	for _, certname := range resp.TLS.PeerCertificates[0].DNSNames {
	//		if mapGoogleDomain[certname] {
	//			bCert = true
	//			break
	//		}
	//	}

	//	var certGoogle string = ""
	//	//这里可以加入判断.google.com为尾部串，二次鉴别是否
	//	if !bCert {
	//		for _, certGoogle = range resp.TLS.PeerCertificates[0].DNSNames {
	//			if strings.HasSuffix(certGoogle, ".google.com") { //判断尾部
	//				bCert = true
	//				break
	//			}
	//		}
	//	}

	//	var certname string = ""
	//	if len(resp.TLS.PeerCertificates[0].DNSNames) != 0 {
	//		certname = resp.TLS.PeerCertificates[0].DNSNames[0]
	//	}

	//增加检查证书的国家,公司，域名信息，防劫持
	//[+] DnsName google      : 6
	//    [*.appspot.com *.thinkwithgoogle.com *.withgoogle.com appspot.com thinkwithg
	//oogle.com withgoogle.com] 6
	//[M] Peer Cert count     : 3
	//    [US] [Google Inc] *.appspot.com
	//    [US] [Google Inc] Google Internet Authority G2
	//    [US] [GeoTrust Inc.] GeoTrust Global CA

	//完全检查三个证书链
	bCert := true
	if len(resp.TLS.PeerCertificates) == 3 {
		for i, peerCert := range resp.TLS.PeerCertificates {
			//下面为安全，仅用%v方式取数据，如直接用或%s，可能会崩溃,原因Country等都还是[]string格式（可能空指针）
			if fmt.Sprintf("%v", peerCert.Subject.Country) != tagGoCert[i].Country {
				bCert = false
				break
			}
			if fmt.Sprintf("%v", peerCert.Subject.Organization) != tagGoCert[i].Organization {
				bCert = false
				break
			}
			strCommonName := fmt.Sprintf("%v", peerCert.Subject.CommonName)
			if strCommonName != tagGoCert[i].CommonName {
				if !(i == 0 && strCommonName == "appspot.com") { //容错一次第一个cert的尾部名称
					bCert = false
					break
				}
			}
		}
	} else {
		bCert = false
	}

	//判断header中的Server段是否是gws
	bGws := false
	if tagOne.strServer = resp.Header.Get("Server"); tagOne.strServer == "gws" {
		bGws = true
	}

	//准备结果结构
	if bCert {
		tagOne.strTlsTime = fmt.Sprintf("%0.f", timeTls)
	} else {
		tagOne.strTlsTime = "!CertHijack!"
	}
	tagOne.strCert = maptagIpOld[strIp].strOldCert //记录原cert

	//通过信道传送三种结果,到RecveWalk单go程处理
	if bGws && bCert {
		if resp.StatusCode == 200 {
			chtagIpGws <- tagOne
		} else { //StatusCode不是200
			chtagIpUnknow <- tagOne
		}
	} else { //非gws
		chtagIpUnknow <- tagOne
	}
}
