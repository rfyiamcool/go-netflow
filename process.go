package netflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	maxRingSize = 15
)

type Process struct {
	Name         string             `json:"name"`
	Pid          string             `json:"pid"`
	Exe          string             `json:"exe"`
	State        string             `json:"state"`
	InodeCount   int                `json:"inode_count"`
	TrafficStats *trafficStatsEntry `json:"traffic_stats"`

	// todo: use ringbuffer array to reduce gc cost.
	Ring []*trafficEntry `json:"ring"`

	inodes   []string
	revision int
}

func (p *Process) getLastTrafficEntry() *trafficEntry {
	if len(p.Ring) == 0 {
		return nil
	}
	return p.Ring[len(p.Ring)-1]
}

func (p *Process) analyseStats(sec int) {
	var (
		stats = new(trafficStatsEntry)
		thold = time.Now().Add(-time.Duration(sec) * time.Second).Unix()
	)

	// avoid x / 0 to raise exception
	if sec == 0 {
		return
	}

	for _, item := range p.Ring {
		if item.Timestamp < thold {
			continue
		}
		stats.In += item.In
		stats.Out += item.Out
	}

	stats.InRate = stats.In / int64(sec)
	stats.OutRate = stats.Out / int64(sec)
	p.TrafficStats = stats
}

func (po *Process) shrink() {
	if len(po.Ring) >= maxRingSize {
		po.Ring = po.Ring[1:] // reduce size
	}
}

func (po *Process) IncreaseInput(n int64) {
	now := time.Now().Unix()
	if len(po.Ring) == 0 {
		item := &trafficEntry{
			Timestamp: now,
			In:        n,
		}
		po.Ring = append(po.Ring, item)
		return
	}

	po.shrink()

	item := po.Ring[len(po.Ring)-1]
	if item.Timestamp == now {
		item.In += n
		return
	}

	item = &trafficEntry{
		Timestamp: now,
		In:        n,
	}
	po.Ring = append(po.Ring, item)
}

// IncreaseOutput
func (po *Process) IncreaseOutput(n int64) {
	// todo: format code
	now := time.Now().Unix()
	if len(po.Ring) == 0 {
		item := &trafficEntry{
			Timestamp: now,
			Out:       n,
		}
		po.Ring = append(po.Ring, item)
		return
	}

	po.shrink()

	item := po.Ring[len(po.Ring)-1]
	if item.Timestamp == now {
		item.Out += n
		return
	}

	item = &trafficEntry{
		Timestamp: now,
		Out:       n,
	}
	po.Ring = append(po.Ring, item)
}

func (p *Process) copy() *Process {
	return &Process{
		Name:       p.Name,
		Pid:        p.Pid,
		Exe:        p.Exe,
		State:      p.State,
		InodeCount: p.InodeCount,
		TrafficStats: &trafficStatsEntry{
			In:      p.TrafficStats.In,
			Out:     p.TrafficStats.Out,
			InRate:  p.TrafficStats.InRate,
			OutRate: p.TrafficStats.OutRate,
		},
		Ring: p.Ring,
	}
}

type trafficEntry struct {
	Timestamp int64 `json:"timestamp"`
	In        int64 `json:"in"`
	Out       int64 `json:"out"`
}

type trafficStatsEntry struct {
	In         int64 `json:"in"`
	Out        int64 `json:"out"`
	InRate     int64 `json:"in_rate"`
	OutRate    int64 `json:"out_rate"`
	InputEWMA  int64 `json:"input_ewma" valid:"-"`
	OutputEWMA int64 `json:"output_ewma" valid:"-"`
}

func GetProcesses() (map[string]*Process, error) {
	// to improve performance
	files, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return nil, err
	}

	var (
		ppm   = make(map[string]*Process, 1000)
		label = "socket:["
	)

	for _, fpath := range files {
		rules := []string{"fd/0", "fd/1", "fd/2"}
		if matchStringSuffix(fpath, rules) {
			continue
		}

		name, _ := os.Readlink(fpath)

		if !strings.HasPrefix(name, label) {
			continue
		}

		var (
			pid   = strings.Split(fpath, "/")[2]
			inode = name[len(label) : len(name)-1]
		)

		po := ppm[pid]
		if po != nil { // has
			po.inodes = append(po.inodes, inode)
			po.InodeCount = len(po.inodes)
			continue
		}

		exe := getProcessExe(pid)
		pname := getProcessName(exe)
		ppm[pid] = &Process{
			Pid:          pid,
			inodes:       []string{inode},
			InodeCount:   1,
			Name:         pname,
			Exe:          exe,
			TrafficStats: new(trafficStatsEntry),
		}
	}

	return ppm, nil
}

type processController struct {
	sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc

	// key -> pid, val -> process
	dict     map[string]*Process
	revision int

	// key -> inode_num, val -> pid_num
	inodePidMap map[string]string

	// cache
	sortedProcesses sortedProcesses
}

func NewProcessController(ctx context.Context) *processController {
	var (
		size = 1000
	)

	cctx, cancel := context.WithCancel(ctx)
	return &processController{
		ctx:         cctx,
		cancel:      cancel,
		dict:        make(map[string]*Process, size),
		inodePidMap: make(map[string]string, size),
	}
}

func (pm *processController) GetRank(limit int) []*Process {
	pm.RLock()
	defer pm.RUnlock()

	src := pm.sortedProcesses
	if len(src) > limit {
		src = pm.sortedProcesses[:limit]
	}

	// copy object
	res := []*Process{}
	for _, item := range src {
		res = append(res, item.copy())
	}
	return src
}

func (pm *processController) Sort(sec int) []*Process {
	pm.RLock()
	defer pm.RUnlock()

	pos := sortedProcesses{}
	for _, po := range pm.dict {
		po.analyseStats(sec)
		pos = append(pos, po)
	}

	sort.Sort(pos)
	pm.sortedProcesses = pos

	return pos
}

func (pm *processController) Add(pid string, p *Process) {
	pm.Lock()
	defer pm.Unlock()

	pm.dict[pid] = p
}

func (pm *processController) Get(pid string) *Process {
	pm.RLock()
	defer pm.RUnlock()

	return pm.dict[pid]
}

func (pm *processController) GetProcessByInode(inode string) *Process {
	pm.RLock()
	defer pm.RUnlock()

	pid, ok := pm.inodePidMap[inode]
	if !ok {
		return nil
	}

	return pm.dict[pid]
}

func (pm *processController) delete(pid string) {
	pm.Lock()
	defer pm.Unlock()

	delete(pm.dict, pid)
}

func (pm *processController) readIterator(fn func(*Process)) {
	pm.RLock()
	defer pm.RUnlock()

	for _, po := range pm.dict {
		fn(po)
	}
}

func (pm *processController) anyIterator(fn func(*Process)) {
	pm.Lock()
	defer pm.Unlock()

	for _, po := range pm.dict {
		fn(po)
	}
}

func (pm *processController) copy() map[string]*Process {
	ndict := make(map[string]*Process, len(pm.dict))

	pm.RLock()
	defer pm.RUnlock()

	for k, v := range pm.dict {
		ndict[k] = v
	}
	return ndict
}

func (pm *processController) AsyncRun() {
	go pm.Run()
}

func (pm *processController) Run() {
	var (
		interval = 5 * time.Second
		ticker   = time.NewTicker(interval)
	)

	pm.Rescan()

	for {
		select {
		case <-pm.ctx.Done():
			return

		case <-ticker.C:
			pm.Rescan()
		}
	}
}

func (pm *processController) Stop() {
	pm.cancel()
}

func (pm *processController) sortNetflow() string {
	bs, _ := json.MarshalIndent(pm.dict, "", "    ")
	return string(bs)
}

func (pm *processController) analyse() error {
	pm.RLock()
	defer pm.RUnlock()

	for pid, po := range pm.dict {
		fmt.Println(pid, po)
	}

	return nil
}

func (pm *processController) Rescan() error {
	ps, err := GetProcesses()
	if err != nil {
		return err
	}

	pm.Lock()
	defer pm.Unlock()

	pm.revision++

	// add new pid
	for pid, po := range ps {
		pp, ok := pm.dict[pid]
		if ok {
			pp.inodes = po.inodes
			continue // alread exist
		}

		pm.dict[pid] = po
	}

	// del old pid
	for pid, _ := range pm.dict {
		_, ok := ps[pid]
		if ok {
			continue
		}

		delete(pm.dict, pid)
	}

	// inode -> pid
	inodePidMap := make(map[string]string, 1000)
	for pid, po := range ps {
		for _, inode := range po.inodes {
			inodePidMap[inode] = pid
		}
	}
	pm.inodePidMap = inodePidMap // obj reset

	return nil
}

func (pm *processController) Reset() {
	pm.dict = make(map[string]*Process, 1000)
	pm.inodePidMap = make(map[string]string, 1000)
}

// getProcessExe
func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

// getProcessName
func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return strings.Title(name)
}

// findPid unuse
func findPid(inode string) string {
	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid
}

type sortedProcesses []*Process

func (s sortedProcesses) Len() int {
	return len(s)
}

func (s sortedProcesses) Less(i, j int) bool {
	val1 := s[i].TrafficStats.In + s[i].TrafficStats.Out
	val2 := s[j].TrafficStats.In + s[j].TrafficStats.Out
	return val1 > val2
}

func (s sortedProcesses) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
