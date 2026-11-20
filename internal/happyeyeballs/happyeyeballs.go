// Package happyeyeballs races connection attempts across a host's addresses
// (RFC 8305, Happy Eyeballs v2).
//
// It exists for the same reason internal/h3build does: the transport raced its
// HTTP/3 dials and client.Client's HTTP/3 pool dialled the same addresses one
// after another. A QUIC attempt to an address that never answers does not fail,
// so on a dual-stack host whose IPv6 address was dead the pool waited out the
// whole 5 s handshake timeout before trying IPv4, where the transport moved on
// after 250 ms.
package happyeyeballs

import (
	"context"
	"fmt"
	"time"
)

// Race implements RFC 8305 Happy Eyeballs v2 connection racing over n
// candidates. It dials candidate 0, then starts each subsequent candidate after
// attemptDelay — or immediately when an earlier attempt fails — and returns the
// first dial that succeeds, cancelling the rest. A dial that succeeds after the
// race is already won is handed to closeLoser so it isn't leaked. dial must
// honor the context it's given (it is cancelled for the losers).
func Race[T any](ctx context.Context, n int, attemptDelay time.Duration, dial func(ctx context.Context, idx int) (T, error), closeLoser func(T)) (T, error) {
	var zero T
	if n <= 0 {
		return zero, fmt.Errorf("no candidates to dial")
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		val T
		err error
	}
	results := make(chan result, n)

	launched, pending := 0, 0
	launchNext := func() {
		idx := launched
		go func() {
			v, err := dial(raceCtx, idx)
			results <- result{val: v, err: err}
		}()
		launched++
		pending++
	}

	timer := time.NewTimer(attemptDelay)
	defer timer.Stop()
	safeReset := func(d time.Duration) {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d)
	}

	launchNext()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			// The parent cancelled the race. defer cancel() stops the losing
			// dials, but a dial that already succeeded (its result sitting in
			// the buffered channel, or landing right after cancellation) would
			// otherwise leak its *net.Conn / *quic.Conn. Drain the outstanding
			// results and close any that connected — mirror the winner-path
			// drain below. results is buffered to n, so this can't block forever.
			if pending > 0 {
				go func(rem int) {
					for i := 0; i < rem; i++ {
						lr := <-results
						if lr.err == nil {
							closeLoser(lr.val)
						}
					}
				}(pending)
			}
			return zero, ctx.Err()

		case <-timer.C:
			if launched < n {
				launchNext()
			}
			if launched < n {
				safeReset(attemptDelay)
			}

		case r := <-results:
			pending--
			if r.err == nil {
				cancel() // stop the losing dials
				if pending > 0 {
					go func(rem int) {
						for i := 0; i < rem; i++ {
							lr := <-results
							if lr.err == nil {
								closeLoser(lr.val)
							}
						}
					}(pending)
				}
				return r.val, nil
			}
			lastErr = r.err
			// Fail-fast: start the next candidate immediately rather than
			// waiting for the timer.
			if launched < n {
				launchNext()
				if launched < n {
					safeReset(attemptDelay)
				}
			} else if pending == 0 {
				if lastErr == nil {
					lastErr = fmt.Errorf("all dial attempts failed")
				}
				return zero, lastErr
			}
		}
	}
}

// Interleave alternates two address families (first list first) so the
// staggered race tries one of each in turn instead of exhausting one family
// before the other.
func Interleave[T any](first, second []T) []T {
	out := make([]T, 0, len(first)+len(second))
	i, j := 0, 0
	for i < len(first) || j < len(second) {
		if i < len(first) {
			out = append(out, first[i])
			i++
		}
		if j < len(second) {
			out = append(out, second[j])
			j++
		}
	}
	return out
}
