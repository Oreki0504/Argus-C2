package agent

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/collector"
)

func retryDelay(failures int) time.Duration {
	d := 5 * time.Second
	for i := 1; i < failures && d < 5*time.Minute; i++ {
		d *= 2
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}
func jitter(d time.Duration) time.Duration {
	// +/- 10%, capped independently of any server reply.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/5)+1))
	if err != nil {
		return d
	}
	d = d - d/10 + time.Duration(n.Int64())
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	return d
}

// Run does not persist failed telemetry, spawn overlapping collectors, or obey
// server scheduling hints. Every iteration resamples the locally allowed scope.
func (c *Client) Run(ctx context.Context, config collector.Config, once bool, report func(error)) error {
	if err := config.Validate(); err != nil {
		return err
	}
	failures := 0
	for {
		sampleCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		h, err := collector.Collect(sampleCtx, c.node, config)
		cancel()
		if err == nil {
			err = c.Heartbeat(ctx, h)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if report != nil {
			report(err)
		}
		if once {
			return err
		}
		delay := time.Duration(config.IntervalSeconds) * time.Second
		if err != nil {
			if failures < 16 {
				failures++
			}
			delay = retryDelay(failures)
		} else {
			failures = 0
		}
		timer := time.NewTimer(jitter(delay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
