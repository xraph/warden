package warden

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
)

// recordingCheckLogStore is a minimal checklog.Store fake that records
// every entry CreateCheckLog is called with, safe for concurrent use.
type recordingCheckLogStore struct {
	mu      sync.Mutex
	entries []*checklog.Entry
	failAll bool
}

func (s *recordingCheckLogStore) CreateCheckLog(_ context.Context, e *checklog.Entry) error {
	if s.failAll {
		return errors.New("boom")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}
func (s *recordingCheckLogStore) GetCheckLog(context.Context, string, id.CheckLogID) (*checklog.Entry, error) {
	return nil, ErrCheckLogNotFound
}
func (s *recordingCheckLogStore) ListCheckLogs(context.Context, *checklog.QueryFilter) ([]*checklog.Entry, error) {
	return nil, nil
}
func (s *recordingCheckLogStore) CountCheckLogs(context.Context, *checklog.QueryFilter) (int64, error) {
	return 0, nil
}
func (s *recordingCheckLogStore) PurgeCheckLogs(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (s *recordingCheckLogStore) DeleteCheckLogsBySubject(context.Context, string, string, string) (int64, error) {
	return 0, nil
}
func (s *recordingCheckLogStore) DeleteCheckLogsByTenant(context.Context, string) error {
	return nil
}

func (s *recordingCheckLogStore) snapshot() []*checklog.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*checklog.Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// fakeWriterMetrics records CheckLogDropped/CheckLogWritten calls.
type fakeWriterMetrics struct {
	NoopMetrics
	mu      sync.Mutex
	dropped int
	written int
}

func (f *fakeWriterMetrics) CheckLogDropped() {
	f.mu.Lock()
	f.dropped++
	f.mu.Unlock()
}
func (f *fakeWriterMetrics) CheckLogWritten(n int) {
	f.mu.Lock()
	f.written += n
	f.mu.Unlock()
}
func (f *fakeWriterMetrics) snapshot() (dropped, written int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped, f.written
}

func TestCheckLogWriter_EnqueueAndFlushOnStop(t *testing.T) {
	s := &recordingCheckLogStore{}
	w := newCheckLogWriter(s, 100, log.NewNoopLogger(), NoopMetrics{})

	for i := 0; i < 5; i++ {
		w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := len(s.snapshot()); got != 5 {
		t.Fatalf("expected all 5 entries flushed on Stop, got %d", got)
	}
}

func TestCheckLogWriter_FlushesOnTicker(t *testing.T) {
	s := &recordingCheckLogStore{}
	w := newCheckLogWriter(s, 100, log.NewNoopLogger(), NoopMetrics{})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	}()

	w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1"})

	deadline := time.Now().Add(2 * time.Second)
	for len(s.snapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("entry was not flushed by the periodic ticker within the deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckLogWriter_DropsWhenQueueFull(t *testing.T) {
	s := &recordingCheckLogStore{}
	metrics := &fakeWriterMetrics{}
	// Queue size 1, and the writer goroutine isn't given a chance to drain
	// (we enqueue synchronously and check the drop counter immediately),
	// so overflow is deterministic.
	w := newCheckLogWriter(s, 1, log.NewNoopLogger(), metrics)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	}()

	// Flood far more entries than the queue (1) plus one in-flight batch
	// slot can absorb, so at least one is guaranteed to be dropped even
	// though the writer goroutine is concurrently draining.
	for i := 0; i < 1000; i++ {
		w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1"})
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		dropped, _ := metrics.snapshot()
		if dropped > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected at least one CheckLogDropped call for a saturated queue")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCheckLogWriter_EnqueueAfterStopIsDropped(t *testing.T) {
	s := &recordingCheckLogStore{}
	metrics := &fakeWriterMetrics{}
	w := newCheckLogWriter(s, 100, log.NewNoopLogger(), metrics)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1"})

	dropped, _ := metrics.snapshot()
	if dropped != 1 {
		t.Fatalf("expected the post-Stop Enqueue to be dropped and counted, got dropped=%d", dropped)
	}
}

func TestCheckLogWriter_WriteErrorDoesNotBlockOtherEntries(t *testing.T) {
	s := &recordingCheckLogStore{failAll: true}
	metrics := &fakeWriterMetrics{}
	w := newCheckLogWriter(s, 100, log.NewNoopLogger(), metrics)

	for i := 0; i < 3; i++ {
		w.Enqueue(&checklog.Entry{ID: id.NewCheckLogID(), TenantID: "t1"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := len(s.snapshot()); got != 0 {
		t.Fatalf("expected 0 entries recorded when the store always errors, got %d", got)
	}
	_, written := metrics.snapshot()
	if written != 0 {
		t.Fatalf("expected CheckLogWritten to not be called for an all-failing batch, got %d", written)
	}
}
