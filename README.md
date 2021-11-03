## go-netflow

go-netflow, capture process in/out traffic, similar to c Nethogs.

[使用 golang 实现进程级流量监控](https://github.com/rfyiamcool/notes/blob/main/netflow.md)

### refer

refer logic design link

- [https://zhuanlan.zhihu.com/p/49981590](https://zhuanlan.zhihu.com/p/49981590)

refer nethogs source link

- [https://github.com/raboof/nethogs](https://github.com/raboof/nethogs)

### dep

```
yum install libpcap
yum install libpcap-devel
```

### cli usage

netflow cli run:

```
go run cmd/main.go
```

stdout:

```text
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
|   PID   | NAME  |                      EXE                       | INODES | SUM IN | SUM OUT | IN RATE | OUT RATE |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
| 2256431 | Wget  | /usr/bin/wget                                  |      1 | 1.0 MB | 0 B     | 339 kB  | 0 B      |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
| 2257200 | Wrk   | /usr/bin/wrk                                   |      5 | 2.0 MB | 16 kB   | 653 kB  | 5.2 kB   |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
| 3707954 | Java  | /usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java |     10 | 457 B  | 648 B   | 152 B   | 216 B    |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
| 2245136 | Wget  | /usr/bin/wget                                  |      1 | 444 kB | 0 B     | 148 kB  | 0 B      |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
| 2034103 | Nginx | /usr/sbin/nginx                                |     41 | 0 B    | 0 B     | 0 B     | 0 B      |
+---------+-------+------------------------------------------------+--------+--------+---------+---------+----------+
```

### sdk simple usage:

```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rfyiamcool/go-netflow"
)

func main() {
	nf, err := netflow.New(
		netflow.WithCaptureTimeout(5 * time.Second),
	)
	if err != nil {
		panic(err)
	}

	err = nf.Start()
	if err != nil {
		panic(err)
	}
	defer nf.Stop()

	<-nf.Done()

	var (
		limit     = 5
		recentSec = 5
	)

	rank, err := nf.GetProcessRank(limit, recentSec)
	if err != nil {
		panic(err)
	}

	bs, err := json.MarshalIndent(rank, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))
}
```

### how to use sdk of go-netflow:

#### set pcap filename

Don't save pcap file by default. 

`WithStorePcap` option is used to save pcap file, use `tcpdump -nnr {filename}` command to read pcap file.

```
WithStorePcap(fpath string)
```

#### set custom pcap bpf filter.

```
WithPcapFilter(filter string)
```

#### set custom pcap bpf filter.

example:

- host xiaorui.cc and port 80
- src host 123.56.223.52 and (dst port 3389 or 22)

```
WithPcapFilter(filter string)
```

#### limit netflow cpu/mem resource.

```
WithLimitCgroup(cpu float64, mem int)
```

#### set time to capturing packet.

```
WithCaptureTimeout(dur time.Duration)
```

#### set time to rescan process and inode data.

```
WithSyncInterval(dur time.Duration)
```

#### set the number of worker to consume pcap queue.

```
WithWorkerNum(num int)
```

#### set custom context.

```
WithCtx(ctx context.Context)
```

#### set custom devices to capture.

```
WithBindDevices(devs []string)
```

#### set pcap queue size. if the queue is full, new packet is thrown away.

```
WithQueueSize(size int)
```

### types

netflow.Interface

```go
type Interface interface {
	Start() error
	Stop()
	Done() <-chan struct{}
	LoadCounter() int64
	GetProcessRank(int, int) ([]*Process, error)
}
```

netflow.Process

```go
type Process struct {
	Name         string
	Pid          string
	Exe          string
	State        string
	Inodes       []string
	TrafficStats *trafficStatsEntry
	Ring         []*trafficEntry
}
```

netflow.trafficStatsEntry

```go
type trafficStatsEntry struct {
	In         int64 `json:"in"`
	Out        int64 `json:"out"`
	InRate     int64 `json:"in_rate"`
	OutRate    int64 `json:"out_rate"`
	InputEWMA  int64 `json:"input_ewma" valid:"-"`
	OutputEWMA int64 `json:"output_ewma" valid:"-"`
}
```

netflow.trafficEntry

```go
type trafficEntry struct {
	Timestamp int64 `json:"timestamp"`
	In        int64 `json:"in"`
	Out       int64 `json:"out"`
}
```
