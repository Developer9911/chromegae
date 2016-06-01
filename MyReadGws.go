package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

//用于记录原有文件中的两字段
type tagIpOld struct {
	strOldCert   string //证书
	strOldServer string //gws小写串,不打算对非gws排序,该结构还用于写入非gws的ip
}

var maptagIpOld = make(map[string]tagIpOld)

//读取待检查.txt文件，解析后,ip全部追加到slice DWORD中,并生成map（ip为索引的, cert,server）
func parseCheckFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	nLineNum := 0
	for scanner.Scan() {
		strLine := scanner.Text() //读取一行
		nLineNum++

		//跳过注释行和空行，注释符号: 前缀为#或前缀为//
		if strings.HasPrefix(strLine, "#") || strings.HasPrefix(strLine, "//") || len(strLine) == 0 {
			continue
		}
		if strLine == "" {
			continue
		}

		var tagIpOne tagIpOld         //自动初始化
		ss := strings.Fields(strLine) //以空格切分为slice
		switch len(ss) {
		case 0, 1:
			return fmt.Errorf("错误行:%d, 文件:%s, 字段数过少", nLineNum, file)
		case 2:
		//不做处理，自动初始化前两结构成员string为空
		case 3:
			tagIpOne.strOldCert = ss[2] //cert
		case 4:
			tagIpOne.strOldCert = ss[2]   //cert
			tagIpOne.strOldServer = ss[3] //servername
		default:
			tagIpOne.strOldCert = ss[2]                       //cert
			tagIpOne.strOldServer = strings.Join(ss[3:], " ") //尾部为带空格的servernme,重新连起来
		}

		strIp := ss[0]
		dwIp := inet_strton(strIp)
		if dwIp == 0 {
			return fmt.Errorf("错误行:%d, 文件:%s, ip格式错", nLineNum, file)
		}

		//该行解析成功，加入map, 加入slice dwowrd中
		maptagIpOld[strIp] = tagIpOne //加入map,便于下文使用,注意其他未填写的成员系统会自动初始化为空的
		sdwIp = append(sdwIp, dwIp)
	}

	if len(sdwIp) == 0 {
		return fmt.Errorf("数量为0，ip文件:%s", file)
	}

	return nil
}

//string ip转 uint32 ip
func inet_strton(strIp string) uint32 {
	return inet_sbton(net.ParseIP(strIp))
}

//DWORD 转 []byte
func inet_ntosb(dwIp uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(dwIp & 0xFF)
	bytes[1] = byte((dwIp >> 8) & 0xFF)
	bytes[2] = byte((dwIp >> 16) & 0xFF)
	bytes[3] = byte((dwIp >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

//[]byte 转 DWORD
func inet_sbton(sbIp net.IP) uint32 {
	//注意：net.Ip 类型为 []byte, 长度为16，为特有格式，不要直接取【0】，【1】（为0，尾部【12-15】才是）
	//fmt.Printf("inet_sbton, %d.%d.%d.%d\n", ipnr[12], ipnr[13], ipnr[14], ipnr[15])

	var dwIp uint32
	dwIp += uint32(sbIp[12]) << 24
	dwIp += uint32(sbIp[13]) << 16
	dwIp += uint32(sbIp[14]) << 8
	dwIp += uint32(sbIp[15])
	return dwIp
}

//随机排序
func shuffle(suIp *[]uint32) {
	s := *suIp
	suTemp := make([]uint32, len(s))

	rand.Seed(time.Now().UnixNano()) //必须初始化seed,否则每次rand都是相同的序列

	for i, v := range rand.Perm(len(s)) { //一次性产生随机序列
		suTemp[v] = s[i]
	}
	*suIp = suTemp
}
