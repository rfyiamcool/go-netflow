package netflow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCgroupRun(t *testing.T) {
	nf, err := New(WithLimitCgroup(0.5, 0))
	assert.Equal(t, nil, err)
	nf.Start()

	time.Sleep(60 * time.Second)
	nf.Stop()
	time.Sleep(60 * time.Second)
}
