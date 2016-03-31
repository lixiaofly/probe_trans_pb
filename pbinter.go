package pbinter

import (
	"encoding/binary"
	"fmt"
	//"io/ioutil"
	"net"
	"strings"
	"time"
)

type Pbinter struct {
	Host        string //127.0.0.1:8080
	Timeout     time.Duration
	OffsetRsend int32
	Des         Pbdes
}
type Pbdes struct {
	Iv  []byte
	Key []byte
}

type pbserr struct {
	resend   int
	err      error
	rep      []byte
	sendsize int32
}

func PbSend(data []byte, pbinfo *Pbinter) error {
	if res := tcpSend(data, pbinfo); res.resend == 1 {
		rres := tcpSend(data, pbinfo)
		return rres.err
	} else {
		switch JudEndian() {
		case "bigEndian":
			fmt.Println("this pc is bigEndian")
			if res.err != nil {
				return res.err 
			}
			if big := binary.BigEndian.Uint32(res.rep); big == 4001 {
				//重发位置1
				data[pbinfo.OffsetRsend] = 1
				rres := tcpSend(data, pbinfo)
				return rres.err
			} else {
				return nil
			}
		case "littleEndian":
			fmt.Println("this pc is littleEndian")
			if res.err != nil {
				return res.err 
			}
			if little := binary.LittleEndian.Uint32(res.rep); little == 4001 {
				//重发位置1
				data[pbinfo.OffsetRsend] = 1
				rres := tcpSend(data, pbinfo)
				return rres.err
			} else {
				return nil
			}
		}
	}
	return nil
}

func tcpSend(data []byte, serv *Pbinter) pbserr {
	fmt.Println("tcp send begin")
	//连接
	tcpAddr, err := net.ResolveTCPAddr("tcp4", serv.Host)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("DialTCP failed!")
		return pbserr{0, err, nil, 0}
	}
	defer conn.Close()
	//des加密
	fmt.Println("before des:", data, "len=", len(data))
	desData, _ := DesEncrypt(data, serv.Des.Key, serv.Des.Iv)
	//写
	fmt.Println("send:", desData, "len=", len(desData))
	send, err := conn.Write(desData)
	if err != nil {
		fmt.Println("send failed!")
		return pbserr{1, err, nil, 0}
	}
	buffer := make([]byte, 1024)
	//设置超时
	conn.SetReadDeadline(time.Now().Add(serv.Timeout))
	//读
	rcvn, err := conn.Read(buffer)
	if err != nil {
		fmt.Println(conn.RemoteAddr().String(), " Read error: ", err)
		stemp := fmt.Sprintf("%s", err)
		if strings.Contains(stemp, "timeout") {
			fmt.Println("my result:", "timeout")
		}
		return pbserr{1, err, nil, 0}
	}
	fmt.Println("rcvn=",rcvn)
	result := buffer[:rcvn]
	return pbserr{0, nil, result, int32(send)}
	/*
		//超时判断
		timeout := make(chan bool, 1)
		go func() {
			time.Sleep(serv.Timeout)
			timeout <- true
		}()

		//读
		select {
		case <-conn:
			result, err := ioutil.ReadAll(conn)
			if err != nil {
				fmt.Println("err:Read conn failed!", err)
				return pbserr{1, err, nil, 0}
			}
			return pbserr{0, nil, result, send}
		case <-timeout:
			fmt.Println("Read conn timeout!")
			return pbserr{1, nil, nil, send}
		}
	*/
}
