package agent

import (
	"testing"
	"time"
)

func TestLocalRetryBounds(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{{1, 5 * time.Second}, {2, 10 * time.Second}, {3, 20 * time.Second}, {20, 5 * time.Minute}} {
		if d := retryDelay(tc.attempt); d != tc.want {
			t.Fatalf("attempt %d: %v", tc.attempt, d)
		}
	}
	for i := 0; i < 100; i++ {
		d := jitter(30 * time.Second)
		if d < 27*time.Second || d > 33*time.Second {
			t.Fatal("heartbeat jitter exceeded local limits")
		}
		if jitter(5*time.Minute) > 5*time.Minute {
			t.Fatal("reconnect cap exceeded")
		}
	}
}
