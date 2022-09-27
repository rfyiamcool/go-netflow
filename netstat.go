package netflow

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	procTCPFile  = "/proc/net/tcp"
	procUDPFile  = "/proc/net/udp"
	procTCP6File = "/proc/net/tcp6"
	procUDP6File = "/proc/net/udp6"

	EstablishedSymbol = "01"
	ListenSymbol      = "0A"
)

type ConnectionItem struct {
	Addr        string `json:"addr" valid:"-"`
	ReverseAddr string `json:"reverse_addr" valid:"-"`
	SrcIP       string `json:"ip"`
	SrcPort     string `json:"port"`
	DestIP      string `json:"foreignip"`
	DestPort    string `json:"foreignport"`
	State       string `json:"state"`

	TxQueue       int           `json:"tx_queue" valid:"-"`
	RxQueue       int           `json:"rx_queue" valid:"-"`
	Timer         int8          `json:"timer" valid:"-"`
	TimerDuration time.Duration `json:"timer_duration" valid:"-"`
	Rto           time.Duration // retransmission timeout
	Uid           int
	Uname         string
	Timeout       time.Duration
	Inode         string `json:"inode"`
	Raw           string `json:"raw"`
}

func (ci *ConnectionItem) GetAddr() string {
	return ci.Addr
}

func parseNetworkLines(tp string) ([]string, error) {
	var pf string

	switch tp {
	case "tcp":
		pf = procTCPFile
	case "udp":
		pf = procUDPFile
	case "tcp6":
		pf = procTCP6File
	case "udp6":
		pf = procUDP6File
	default:
		pf = procTCPFile
	}

	data, err := ioutil.ReadFile(pf)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(data, []byte("\n"))
	var netString []string
	fileLens := len(lines)
	for i, line := range lines {
		if i == 0 || i == fileLens-1 {
			continue
		}
		netString = append(netString, string(line))
	}
	return netString, nil
}

func hex2dec(hexstr string) string {
	i, _ := strconv.ParseInt(hexstr, 16, 0)
	return strconv.FormatInt(i, 10)
}

func hex2ip(hexstr string) (string, string) {
	var ip string
	if len(hexstr) != 8 {
		err := "parse error"
		return ip, err
	}

	i1, _ := strconv.ParseInt(hexstr[6:8], 16, 0)
	i2, _ := strconv.ParseInt(hexstr[4:6], 16, 0)
	i3, _ := strconv.ParseInt(hexstr[2:4], 16, 0)
	i4, _ := strconv.ParseInt(hexstr[0:2], 16, 0)
	ip = fmt.Sprintf("%d.%d.%d.%d", i1, i2, i3, i4)

	return ip, ""
}

func parseAddr(str string) (string, string) {
	l := strings.Split(str, ":")
	if len(l) != 2 {
		return str, ""
	}

	ip, err := hex2ip(l[0])
	if err != "" {
		return str, ""
	}

	return ip, hex2dec(l[1])
}

// convert hexadecimal to decimal.
func hexToDec(h string) int64 {
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}

// remove empty data from line
func removeEmpty(array []string) []string {
	var columns []string
	for _, i := range array {
		if i == "" {
			continue
		}
		columns = append(columns, i)
	}
	return columns
}

type filterFunc func()

func netstat(t string) ([]*ConnectionItem, error) {
	var (
		conns []*ConnectionItem
	)

	data, err := parseNetworkLines(t)
	if err != nil {
		return nil, err
	}

	for _, line := range data {
		pp := getConnectionItem(line)
		if pp == nil {
			continue
		}

		conns = append(conns, pp)
	}

	return conns, nil
}

func getConnectionItem(line string) *ConnectionItem {
	// local ip and port
	source := removeEmpty(strings.Split(strings.TrimSpace(line), " "))

	// only notice ESTAB and listen state
	if source[3] != EstablishedSymbol && source[3] != ListenSymbol {
		return nil
	}

	// ignore local listenning records
	destIP, destPort := parseAddr(source[2])
	if destIP == "0.0.0.0" {
		return nil
	}

	// source ip and port
	ip, port := parseAddr(source[1])

	// connection info
	stateNum, _ := strconv.ParseInt(source[3], 16, 32)
	state := states[int(stateNum)]

	// parse tx, rx queue size
	tcpQueue := strings.Split(source[4], ":")
	txq, err := strconv.ParseInt(tcpQueue[0], 16, 32) // tx queue size
	if err != nil {
		return nil
	}

	rxq, err := strconv.ParseInt(tcpQueue[1], 16, 32) // rx queue size
	if err != nil {
		return nil
	}

	// socket uid
	uid, err := strconv.Atoi(source[7])
	if err != nil {
		return nil
	}

	// get user name by uid
	uname := getUserByUID(source[7])

	// socket inode
	inode := source[9]

	// tcp 4 fileds
	addr := ip + ":" + port + "_" + destIP + ":" + destPort
	raddr := destIP + ":" + destPort + "_" + ip + ":" + port

	cc := &ConnectionItem{
		Addr:        addr,
		ReverseAddr: raddr,
		State:       state,
		SrcIP:       ip,
		SrcPort:     port,
		DestIP:      destIP,
		DestPort:    destPort,
		Inode:       inode,
		TxQueue:     int(txq),
		RxQueue:     int(rxq),
		Uid:         uid,
		Uname:       uname,
		Raw:         line,
	}
	return cc
}

// Tcp func Get a slice of Process type with TCP data
func Tcp() []*ConnectionItem {
	data, _ := netstat("tcp")
	return data
}

// Udp func Get a slice of Process type with UDP data
func Udp() []*ConnectionItem {
	data, _ := netstat("udp")
	return data
}

// Tcp6 func Get a slice of Process type with TCP6 data
func Tcp6() []*ConnectionItem {
	data, _ := netstat("tcp6")
	return data
}

// Udp6 func Get a slice of Process type with UDP6 data
func Udp6() []*ConnectionItem {
	data, _ := netstat("udp6")
	return data
}
