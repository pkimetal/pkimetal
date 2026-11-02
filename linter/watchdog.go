package linter

import (
	"context"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"go.uber.org/zap"
)

// A goroutine cannot be killed, so an in-process linter instance that hangs
// cannot be recovered without restarting pkimetal; and replacing it with a new
// instance would let hung goroutines accumulate without bound.  Instead, an
// in-process instance that has been processing one request for longer than
// linter.backendTimeout is reported as stuck: it is logged, counted in the
// pkimetal_linter_stuck_instances metric, and causes /livez to fail, so that an
// orchestrator can restart pkimetal.

const watchdogInterval = time.Second

// isWatched reports whether this instance runs its linter in-process.  External
// backends are instead bounded by I/O deadlines and restarted on failure.
func (lin *LinterInstance) isWatched() bool {
	return lin.useHandleRequest && !lin.external
}

// stuckFor returns how long this instance has been processing its current
// request, if that exceeds linter.backendTimeout; otherwise it returns 0.
func (lin *LinterInstance) stuckFor(now time.Time) time.Duration {
	if !lin.isWatched() {
		return 0
	}
	busySince := lin.busySince.Load()
	if busySince == 0 {
		return 0
	}
	if busyFor := now.Sub(time.Unix(0, busySince)); busyFor > config.Config.Linter.BackendTimeout {
		return busyFor
	}
	return 0
}

// AnyInstanceStuck reports whether any in-process linter instance is stuck.
func AnyInstanceStuck() bool {
	now := time.Now()
	for _, lin := range linterInstances {
		if lin.stuckFor(now) > 0 {
			return true
		}
	}
	return false
}

// registerStuckInstancesMetric registers a gauge that reports how many of the
// linter's instances are stuck.
func (l *Linter) registerStuckInstancesMetric() prometheus.GaugeFunc {
	return promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace:   config.ApplicationNamespace,
		Subsystem:   "linter",
		Name:        "stuck_instances",
		Help:        "Number of in-process linter instances that have been processing one request for longer than the backend timeout.",
		ConstLabels: map[string]string{"linter_name": l.Name},
	}, func() float64 {
		now := time.Now()
		n := 0
		for _, lin := range linterInstances {
			if lin.Linter == l && lin.stuckFor(now) > 0 {
				n++
			}
		}
		return float64(n)
	})
}

// runWatchdog logs when in-process linter instances become stuck and when they
// recover, until ctx is done.
func runWatchdog(ctx context.Context, interval time.Duration) {
	stuck := make(map[*LinterInstance]bool)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, lin := range linterInstances {
				busyFor := lin.stuckFor(now)
				if busyFor > 0 && !stuck[lin] {
					stuck[lin] = true
					logger.Logger.Error("Linter instance is stuck; restart pkimetal to recover it", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name), zap.Duration("busy_for", busyFor))
				} else if busyFor == 0 && stuck[lin] {
					delete(stuck, lin)
					logger.Logger.Warn("Linter instance is no longer stuck", zap.Int("instance#", lin.instanceNumber), zap.String("name", lin.Name))
				}
			}
		}
	}
}
