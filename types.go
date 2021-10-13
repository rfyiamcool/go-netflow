package netflow

import (
	"encoding/json"
	"fmt"
	"sync"
)

const (
	TCP_ESTABLISHED = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	//TCP_NEW_SYN_RECV
	//TCP_MAX_STATES
)

var states = map[int]string{
	TCP_ESTABLISHED: "ESTABLISHED",
	TCP_SYN_SENT:    "SYN_SENT",
	TCP_SYN_RECV:    "SYN_RECV",
	TCP_FIN_WAIT1:   "FIN_WAIT1",
	TCP_FIN_WAIT2:   "FIN_WAIT2",
	TCP_TIME_WAIT:   "TIME_WAIT",
	TCP_CLOSE:       "CLOSE",
	TCP_CLOSE_WAIT:  "CLOSE_WAIT",
	TCP_LAST_ACK:    "LAST_ACK",
	TCP_LISTEN:      "LISTEN",
	TCP_CLOSING:     "CLOSING",
	//TCP_NEW_SYN_RECV: "NEW_SYN_RECV",
	//TCP_MAX_STATES:   "MAX_STATES",
}

// https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
var StateMapping = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type Mapping struct {
	cb   func()
	dict map[string]string
	sync.RWMutex
}

func NewMapping() *Mapping {
	size := 1000
	return &Mapping{
		dict: make(map[string]string, size),
	}
}

func (m *Mapping) Handle() {
}

func (m *Mapping) Add(k, v string) {
	m.Lock()
	defer m.Unlock()

	m.dict[k] = v
}

func (m *Mapping) Get(k string) string {
	m.RLock()
	defer m.RUnlock()

	return m.dict[k]
}

func (m *Mapping) Delete(k string) {
	m.Lock()
	defer m.Unlock()

	delete(m.dict, k)
}

func (m *Mapping) String() string {
	m.RLock()
	defer m.RUnlock()

	bs, _ := json.Marshal(m.dict)
	return string(bs)
}

type Null struct{}

type LoggerInterface interface {
	Debug(...interface{})
	Error(...interface{})
}

var defaultLogger string

type logger struct{}

func (l *logger) Debug(msg ...interface{}) {
	fmt.Println(msg...)
}

func (l *logger) Error(msg ...interface{}) {
	fmt.Println(msg...)
}
