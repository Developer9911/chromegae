//My对结构体slice排序
package main

import "strconv"

type tagIpRecod struct {
	strIp      string //ip地址
	strTlsTime string //tls握手速度
	strCert    string //证书
	strServer  string //gws小写串,不打算对非gws排序,该结构还用于写入非gws的ip
}

//实现了如下的方法后，即可调用 sort.Sort(slice结构变量名)
type stagIpRecords []tagIpRecod

func (s stagIpRecords) Len() int {
	return len(s)
}

func (s stagIpRecords) Less(i, j int) bool {
	return MyAtoi(s[i].strTlsTime) < MyAtoi(s[j].strTlsTime) //必须转为整数再比较，否则串比较规则与整数比较规则不同
}

func (s stagIpRecords) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

//改两返回为一返回，便于Less调用
func MyAtoi(str string) int64 {
	n, err := strconv.ParseInt(str, 10, 0) //或者strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return n
}
