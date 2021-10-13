## go-netflow

go-netflow, similar to c Nethogs.

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

### api usage

#### simple usage:

```go

import (
	"github.com/rfyiamcool/go-netflow"
)

func main() {
	nf, err = netflow.New()
	if err != nil {
		panic(err)
	}

	err = nf.Start()
	if err != nil {
		panic(err)
	}
	defer nf.Stop()


	var (
		limit = 5
		windowsInterval = 3
	)

	rank, err := nf.GetProcessRank(limit, windowsInterval)
	fmt.Println(rank)
	fmt.Println(err)
}
```

#### how to new netflow objcet:

set custom pcap bpf filter.

```
WithPcapFilter(filter string)
```

limit netflow cpu/mem resource.

```
WithLimitCgroup(cpu float64, mem int)
```

set time to capturing packet.

```
WithCaptureTimeout(dur time.Duration)
```

set time to rescan process and inode data.

```
WithSyncInterval(dur time.Duration)
```

set the number of worker to consume pcap queue.

```
WithWorkerNum(num int)
```

set custom context.

```
WithCtx(ctx context.Context)
```

set custom devices to capture.

```
WithBindDevices(devs []string)
```

set pcap queue size. if the queue is full, new packet is thrown away.

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
