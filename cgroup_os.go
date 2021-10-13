// +build !linux

package netflow

import (
	"errors"
)

type cgroupsLimiter struct {
}

func (r *cgroupsLimiter) free() error {
	return nil
}

func (r *cgroupsLimiter) configure(pid int, core float64, mb int) error {
	return errors.New("don't support cgroup")
}
