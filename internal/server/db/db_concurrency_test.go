package db

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

func openFileTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err, "Open")
	t.Cleanup(func() { s.Close() })
	return s
}

// A file DB opens in WAL with a busy timeout so the background updater's writes
// don't collide with request reads (see dataSource).
func TestFileDBUsesWALAndBusyTimeout(t *testing.T) {
	s := openFileTest(t)

	var journalMode string
	var busyTimeout int
	require.NoError(t, s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode))
	require.NoError(t, s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout))

	assert.Equal(t, "wal", journalMode)
	assert.Equal(t, 5000, busyTimeout)
}

// Regression: concurrent writers (the updater) and readers (a /collect cache
// lookup) must not make reads error. A read error gets swallowed as a cache
// miss upstream, which triggers a needless live refetch. Before WAL +
// busy_timeout this produced tens of thousands of SQLITE_BUSY read errors.
func TestConcurrentReadsDontError(t *testing.T) {
	s := openFileTest(t)
	ctx := context.Background()
	comp := collect.Component{SPURL: "pkg:npm/axios", Name: "axios", FetchedAt: time.Now().UTC()}
	require.NoError(t, s.PutComponent(ctx, comp))

	var readErrs int64
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c := comp
				c.FetchedAt = time.Now().UTC()
				_ = s.PutComponent(ctx, c)
			}
		}()
	}
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := s.GetComponent(ctx, comp.SPURL); err != nil {
					atomic.AddInt64(&readErrs, 1)
				}
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	assert.Zero(t, readErrs, "reads errored under write contention")
}
