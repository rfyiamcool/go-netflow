package netflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStringSuffix(t *testing.T) {
	cur := "/proc/123123/fd/3"
	b := matchStringSuffix(cur, []string{"fd/0", "fd/1", "fd2"})
	assert.Equal(t, false, b)

	cur = "/proc/123123/fd/2"
	b = matchStringSuffix(cur, []string{"fd/0", "fd/1", "fd/2"})
	assert.Equal(t, true, b)

	cur = "/proc/123123/fd/11"
	b = matchStringSuffix(cur, []string{"fd/0", "fd/1", "fd2"})
	assert.Equal(t, false, b)
}

func TestGetProcesses(t *testing.T) {
	pps, err := GetProcesses()
	assert.Equal(t, nil, err)

	bs, err := json.MarshalIndent(pps, "", "  ")
	assert.Equal(t, nil, err)

	fmt.Printf("%+v", string(bs))
}

func TestProcessHash(t *testing.T) {
	pm := NewProcessController(context.Background())
	go pm.Run()

	time.Sleep(3 * time.Second)

	t.Log(MarshalIndent(pm.dict))
	t.Log(MarshalIndent(pm.inodePidMap))
	pm.Stop()
}

func TestProcessShrink(t *testing.T) {
	po := Process{}
	for i := 0; i < 15; i++ {
		po.IncreaseInput(10)
		time.Sleep(1 * time.Second)
	}
	assert.Equal(t, 10, len(po.Ring))
}

func TestProcessAnalyse(t *testing.T) {
	po := Process{}
	po.IncreaseInput(10)
	time.Sleep(1 * time.Second)

	po.IncreaseInput(50)
	time.Sleep(1 * time.Second)

	po.IncreaseInput(100)
	time.Sleep(1 * time.Second)

	// in
	po.IncreaseInput(50)
	po.IncreaseInput(50)
	po.IncreaseInput(50)
	// out
	po.IncreaseOutput(50)
	po.IncreaseOutput(50)
	time.Sleep(1 * time.Second)

	assert.EqualValues(t, 150, po.getLastTrafficEntry().In)
	assert.EqualValues(t, 100, po.getLastTrafficEntry().Out)

	t.Log(MarshalIndent(po))

	po.analyseStats(2)
	t.Log(MarshalIndent(po))
}

func TestProcessAnalyse2(t *testing.T) {
	po := Process{}

	for i := 0; i < 20; i++ {
		po.IncreaseInput(10)
		time.Sleep(1 * time.Second)
	}

	po.analyseStats(2)
	assert.EqualValues(t, 20, po.TrafficStats.In)
}

func TestSortedProcesses(t *testing.T) {
	pps := []*Process{}

	p1 := &Process{
		Pid: "111",
		TrafficStats: &trafficStatsEntry{
			In:      100,
			Out:     100,
			InRate:  100,
			OutRate: 100,
		},
	}

	p2 := &Process{
		Pid: "222",
		TrafficStats: &trafficStatsEntry{
			In:      200,
			Out:     200,
			InRate:  200,
			OutRate: 200,
		},
	}

	p3 := &Process{
		Pid: "333",
		TrafficStats: &trafficStatsEntry{
			In:      300,
			Out:     300,
			InRate:  300,
			OutRate: 300,
		},
	}

	p4 := &Process{
		Pid: "444",
		TrafficStats: &trafficStatsEntry{
			In:      400,
			Out:     400,
			InRate:  400,
			OutRate: 400,
		},
	}

	// don't insert in order !
	pps = append(pps, p4)
	pps = append(pps, p1)
	pps = append(pps, p3)
	pps = append(pps, p2)

	sort.Sort(sortedProcesses(pps))

	t.Log(MarshalIndent(pps))

	link := []*Process{p4, p3, p2, p1} // desc sort
	for idx := range link {
		assert.Equal(t, link[idx].Pid, pps[idx].Pid)
	}
}
