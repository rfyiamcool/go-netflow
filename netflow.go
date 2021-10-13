package netflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sync/errgroup"
)

var (
	errNotFound = errors.New("not found")
)

type sideOption int

const (
	inputSide sideOption = iota
	outputSide
)

type Netflow struct {
	ctx    context.Context
	cancel context.CancelFunc

	connInodeHash *Mapping
	processHash   *processController
	workerNum     int
	qsize         int

	// for update action
	delayQueue  chan *delayEntry
	packetQueue chan gopacket.Packet

	bindIPs        map[string]nullObject // read only
	bindDevices    map[string]nullObject // read only
	counter        int64
	captureTimeout time.Duration
	syncInterval   time.Duration
	pcapFilter     string // for pcap filter

	// for debug
	debugMode bool
	logger    LoggerInterface

	// for cgroup
	cpuCore float64
	memMB   int

	exitFunc []func()
	timer    *time.Timer
}

type optionFunc func(*Netflow) error

// WithPcapFilter set custom pcap filter
// filter: "port 80", "src host xiaorui.cc and port 80"
func WithPcapFilter(filter string) optionFunc {
	return func(o *Netflow) error {
		if len(filter) == 0 {
			return nil
		}

		st := strings.TrimSpace(filter)
		if strings.HasPrefix(st, "and") {
			return errors.New("invalid pcap filter")
		}

		o.pcapFilter = filter
		return nil
	}
}

func WithOpenDebug() optionFunc {
	return func(o *Netflow) error {
		o.debugMode = true
		return nil
	}
}

// WithLimitCgroup use cgroup to limit cpu and mem, param cpu's unit is cpu core num , mem's unit is MB
func WithLimitCgroup(cpu float64, mem int) optionFunc {
	return func(o *Netflow) error {
		o.cpuCore = cpu
		o.memMB = mem
		return nil
	}
}

func WithLogger(logger LoggerInterface) optionFunc {
	return func(o *Netflow) error {
		o.logger = logger
		return nil
	}
}

func WithCaptureTimeout(dur time.Duration) optionFunc {
	// capture name
	if dur > defaultCaptureTimeout {
		dur = defaultCaptureTimeout
	}

	return func(o *Netflow) error {
		o.captureTimeout = dur
		return nil
	}
}

func WithSyncInterval(dur time.Duration) optionFunc {
	return func(o *Netflow) error {
		if dur <= 0 {
			return errors.New("invalid sync interval")
		}

		o.syncInterval = dur
		return nil
	}
}

func WithWorkerNum(num int) optionFunc {
	if num <= 0 {
		num = defaultWorkerNum // default
	}

	return func(o *Netflow) error {
		o.workerNum = num
		return nil
	}
}

func WithCtx(ctx context.Context) optionFunc {
	return func(o *Netflow) error {
		cctx, cancel := context.WithCancel(ctx)
		o.ctx = cctx
		o.cancel = cancel
		return nil
	}
}

func WithBindIPs(ips []string) optionFunc {
	return func(o *Netflow) error {
		if len(ips) == 0 {
			return errors.New("invalid ips")
		}

		mm := make(map[string]nullObject, 10)
		for _, ip := range ips {
			mm[ip] = nullObject{}
		}

		o.bindIPs = mm
		return nil
	}
}

func WithBindDevices(devs []string) optionFunc {
	return func(o *Netflow) error {
		if len(devs) == 0 {
			return errors.New("invalid devs")
		}

		mm := make(map[string]nullObject, 10)
		for _, dev := range devs {
			mm[dev] = nullObject{}
		}

		o.bindDevices = mm
		return nil
	}
}

func WithQueueSize(size int) optionFunc {
	if size < 1000 {
		size = defaultQueueSize
	}

	return func(o *Netflow) error {
		o.qsize = size
		return nil
	}
}

const (
	defaultQueueSize      = 20000 // 2w
	defaultWorkerNum      = 1     // usually one worker is enough.
	defaultSyncInterval   = time.Duration(1 * time.Second)
	defaultCaptureTimeout = time.Duration(300 * time.Second)
)

type Interface interface {
	// start netflow
	Start() error

	// stop netflow
	Stop()

	// sum packet
	LoadCounter() int64

	// when ctx.cancel() or timeout, notify done.
	Done() <-chan struct{}

	// GetProcessRank
	// param limit, size of data returned.
	// param recentSeconds, the average of the last few seconds' value.
	GetProcessRank(limit int, recentSeconds int) ([]*Process, error)
}

func New(opts ...optionFunc) (Interface, error) {
	var (
		ctx, cancel = context.WithCancel(context.Background())
	)

	ips, devs := parseIpaddrsAndDevices()
	nf := &Netflow{
		ctx:            ctx,
		cancel:         cancel,
		bindIPs:        ips,
		bindDevices:    devs,
		qsize:          defaultQueueSize,
		workerNum:      defaultWorkerNum,
		captureTimeout: defaultCaptureTimeout,
		syncInterval:   defaultSyncInterval,
		debugMode:      false,
		logger:         &logger{},
	}

	for _, opt := range opts {
		err := opt(nf)
		if err != nil {
			return nil, err
		}
	}

	nf.packetQueue = make(chan gopacket.Packet, nf.qsize)
	nf.delayQueue = make(chan *delayEntry, nf.qsize)
	nf.connInodeHash = NewMapping()
	nf.processHash = NewProcessController(nf.ctx)

	return nf, nil
}

func (nf *Netflow) Done() <-chan struct{} {
	return nf.ctx.Done()
}

func (nf *Netflow) GetProcessRank(limit int, recentSeconds int) ([]*Process, error) {
	if recentSeconds > maxRingSize {
		return nil, errors.New("windows interval must <= 15")
	}

	nf.processHash.Sort(recentSeconds)
	prank := nf.processHash.GetRank(limit)
	return prank, nil
}

func (nf *Netflow) incrCounter() {
	atomic.AddInt64(&nf.counter, 1)
}

func (nf *Netflow) LoadCounter() int64 {
	return atomic.LoadInt64(&nf.counter)
}

func (nf *Netflow) configureCgroups() error {
	if nf.cpuCore == 0 && nf.memMB == 0 {
		return nil
	}

	cg := cgroupsLimiter{}
	pid := os.Getpid()

	err := cg.configure(pid, nf.cpuCore, nf.memMB)
	nf.exitFunc = append(nf.exitFunc, func() {
		cg.free()
	})

	return err
}

func (nf *Netflow) Start() error {
	// linux cpu/mem by cgroup
	err := nf.configureCgroups()
	if err != nil {
		return err
	}

	// start workers
	go nf.startResourceSyncer()
	go nf.startNetworkSniffer()

	return nil
}

func (nf *Netflow) Stop() {
	nf.cancel()
	nf.finalize()
}

func (nf *Netflow) finalize() {
	if nf.timer != nil {
		nf.timer.Stop()
	}

	for _, fn := range nf.exitFunc {
		fn()
	}
}

func (nf *Netflow) startResourceSyncer() {
	var (
		ticker   = time.NewTicker(nf.syncInterval)
		entry    *delayEntry
		lastTime time.Time
	)

	// first run at the beginning
	nf.rescanResouce()

	for {
		select {
		case <-nf.ctx.Done():
			return
		case <-ticker.C:
			nf.rescanResouce()
			lastTime = time.Now()

			// after rescan, handle undo entries
			for {
				if entry == nil {
					entry = nf.consumeDelayQueue()
				}
				// queue is empty
				if entry == nil {
					break
				}

				// only hanlde entry before rescan.
				if entry.timestamp.After(lastTime) {
					break
				}

				nf.handleDelayEntry(entry)
				entry = nil
			}
		}
	}
}

func (nf *Netflow) rescanResouce() error {
	var wg errgroup.Group

	wg.Go(func() error {
		return nf.rescanConns()
	})
	wg.Go(func() error {
		return nf.rescanProcessInodes()
	})

	return wg.Wait()
}

func (nf *Netflow) rescanProcessInodes() error {
	return nf.processHash.Rescan()
}

func (nf *Netflow) rescanConns() error {
	conns, err := netstat("tcp")
	if err != nil {
		return err
	}

	for _, conn := range conns {
		nf.connInodeHash.Add(conn.Addr, conn.Inode)
		nf.connInodeHash.Add(conn.ReverseAddr, conn.Inode)
	}

	return nil
}

func (nf *Netflow) captureDevice(dev string) {
	handler, err := buildPcapHandler(dev, nf.captureTimeout, nf.pcapFilter)
	if err != nil {
		return
	}

	defer func() {
		handler.Close()
	}()

	packetSource := gopacket.NewPacketSource(
		handler,
		handler.LinkType(),
	)

	for {
		select {
		case <-nf.ctx.Done():
			return

		case pkt := <-packetSource.Packets():
			nf.enqueue(pkt)
		}
	}
}

func (nf *Netflow) enqueue(pkt gopacket.Packet) {
	select {
	case nf.packetQueue <- pkt:
		nf.incrCounter()
		return
	default:
		nf.logError("queue overflow, current size: ", len(nf.packetQueue))
	}
}

func (nf *Netflow) dequeue() gopacket.Packet {
	select {
	case pkt := <-nf.packetQueue:
		return pkt

	case <-nf.ctx.Done():
		return nil
	}
}

func (nf *Netflow) loopHandlePacket() {
	for {
		pkt := nf.dequeue()
		if pkt == nil {
			return // ctx.Done
		}

		nf.handlePacket(pkt)
	}
}

func (nf *Netflow) handlePacket(packet gopacket.Packet) {
	// var (
	// 	ethLayer layers.Ethernet
	// 	ipLayer  layers.IPv4
	// 	tcpLayer layers.TCP

	// 	layerTypes = []gopacket.LayerType{}
	// )

	// parser := gopacket.NewDecodingLayerParser(
	// 	layers.LayerTypeEthernet,
	// 	&ethLayer,
	// 	&ipLayer,
	// 	&tcpLayer,
	// )

	// err := parser.DecodeLayers(packet.Data(), &layerTypes)
	// if err != nil {
	// 	continue
	// }

	// get ipLayer
	_ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if _ipLayer == nil {
		return
	}
	ipLayer, _ := _ipLayer.(*layers.IPv4)

	// get tcpLayer
	_tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if _tcpLayer == nil {
		return
	}
	tcpLayer, _ := _tcpLayer.(*layers.TCP)

	var (
		side sideOption

		localIP   = ipLayer.SrcIP
		localPort = tcpLayer.SrcPort

		remoteIP   = ipLayer.DstIP
		remotePort = tcpLayer.DstPort
	)

	if nf.isBindIPs(ipLayer.SrcIP.String()) {
		side = outputSide
	} else {
		side = inputSide
	}

	// length := len(packet.Data())
	length := len(tcpLayer.Payload)
	addr := spliceAddr(localIP, localPort, remoteIP, remotePort)
	nf.increaseTraffic(addr, int64(length), side)

	// fmt.Println(">>>>", addr, len(packet.Data()), len(tcpLayer.Payload), side)
}

func (nf *Netflow) logDebug(msg ...interface{}) {
	if !nf.debugMode {
		return
	}

	nf.logger.Debug(msg...)
}

func (nf *Netflow) logError(msg ...interface{}) {
	if !nf.debugMode {
		return
	}

	nf.logger.Error(msg...)
}

func (nf *Netflow) isBindIPs(ipa string) bool {
	_, ok := nf.bindIPs[ipa]
	return ok
}

func (nf *Netflow) startNetworkSniffer() {
	for dev := range nf.bindDevices {
		go nf.captureDevice(dev)
	}

	for i := 0; i < nf.workerNum; i++ {
		go nf.loopHandlePacket()
	}

	nf.timer = time.AfterFunc(nf.captureTimeout,
		func() {
			nf.Stop()
		},
	)
}

type delayEntry struct {
	// meta
	timestamp time.Time
	times     int

	// data
	addr   string
	length int64
	side   sideOption
}

func (nf *Netflow) pushDelayQueue(de *delayEntry) {
	select {
	case nf.delayQueue <- de:
	default:
		// if q is full, drain actively .
	}
}

func (nf *Netflow) consumeDelayQueue() *delayEntry {
	select {
	case <-nf.ctx.Done():
		return nil

	case den := <-nf.delayQueue:
		return den

	default:
		return nil
	}
}

func (nf *Netflow) handleDelayEntry(entry *delayEntry) error {
	proc, err := nf.getProcessByAddr(entry.addr)
	if err != nil {
		return err
	}

	nf.increaseProcessTraffic(proc, entry.length, entry.side)
	return nil
}

func (nf *Netflow) getProcessByAddr(addr string) (*Process, error) {
	inode := nf.connInodeHash.Get(addr)
	if len(inode) == 0 {
		// not found, to rescan
		nf.logDebug("not found inode ", addr)
		return nil, errNotFound
	}

	proc := nf.processHash.GetProcessByInode(inode)
	if proc == nil {
		// not found, to rescan
		nf.logDebug("not found proc ", addr)
		return nil, errNotFound
	}

	return proc, nil
}

func (nf *Netflow) increaseProcessTraffic(proc *Process, length int64, side sideOption) error {
	switch side {
	case inputSide:
		proc.IncreaseInput(length)
	case outputSide:
		proc.IncreaseOutput(length)
	}
	return nil
}

func (nf *Netflow) increaseTraffic(addr string, length int64, side sideOption) error {
	proc, err := nf.getProcessByAddr(addr)
	if err != nil {
		den := &delayEntry{
			timestamp: time.Now(),
			times:     0,
			addr:      addr,
			length:    length,
			side:      side,
		}
		nf.pushDelayQueue(den)
		return err
	}

	nf.increaseProcessTraffic(proc, length, side)
	return nil
}

type nullObject = struct{}

func parseIpaddrsAndDevices() (map[string]nullObject, map[string]nullObject) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, nil
	}

	var (
		bindIPs  = map[string]nullObject{}
		devNames = map[string]nullObject{}
	)

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.IsMulticast() {
				continue
			}
			bindIPs[addr.IP.String()] = struct{}{}
		}

		if strings.HasPrefix(dev.Name, "eth") {
			devNames[dev.Name] = nullObject{}
			continue
		}

		if strings.HasPrefix(dev.Name, "em") {
			devNames[dev.Name] = nullObject{}
			continue
		}

		if strings.HasPrefix(dev.Name, "lo") {
			devNames[dev.Name] = nullObject{}
			continue
		}

		if strings.HasPrefix(dev.Name, "bond") {
			devNames[dev.Name] = nullObject{}
			continue
		}
	}
	return bindIPs, devNames
}

func buildPcapHandler(device string, timeout time.Duration, pfilter string) (*pcap.Handle, error) {
	var (
		snapshotLen int32 = 65536
		promisc     bool  = false
	)

	// if packet captured size >= snapshotLength or 1 second's timer is expired, call user layer.
	handler, err := pcap.OpenLive(device, snapshotLen, promisc, time.Second)
	if err != nil {
		return nil, err
	}

	var filter = "tcp and (not broadcast and not multicast)"
	if len(pfilter) != 0 {
		filter = fmt.Sprintf("%s and %s", filter, pfilter)
	}

	err = handler.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}

	return handler, nil
}

func spliceAddr(sip net.IP, sport layers.TCPPort, dip net.IP, dport layers.TCPPort) string {
	return fmt.Sprintf("%s:%d_%s:%d", sip, sport, dip, dport)
}
