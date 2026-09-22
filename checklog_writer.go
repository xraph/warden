package warden

import (
	"context"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/checklog"
)

// checkLogBatchSize is the maximum number of entries the writer batches
// into one flush.
const checkLogBatchSize = 100

// checkLogFlushInterval is the maximum time an entry waits in a
// not-yet-full batch before it is flushed anyway.
const checkLogFlushInterval = 250 * time.Millisecond

// checkLogWriter batches check log entries onto a single background
// goroutine and writes them to the store, so Check never blocks on
// persistence and never spawns a goroutine per call. The queue is bounded:
// when full, new entries are dropped and Metrics.CheckLogDropped is
// incremented rather than applying backpressure to Check.
type checkLogWriter struct {
	store   checklog.Store
	logger  log.Logger
	metrics Metrics

	queue chan *checklog.Entry
	wg    sync.WaitGroup

	mu      sync.RWMutex
	stopped bool
}

func newCheckLogWriter(s checklog.Store, queueSize int, logger log.Logger, metrics Metrics) *checkLogWriter {
	if queueSize <= 0 {
		queueSize = 4096
	}
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	if metrics == nil {
		metrics = NoopMetrics{}
	}
	w := &checkLogWriter{
		store:   s,
		logger:  logger,
		metrics: metrics,
		queue:   make(chan *checklog.Entry, queueSize),
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Enqueue adds an entry to the write queue. Never blocks: when the queue is
// full, or the writer has been stopped, the entry is dropped and
// Metrics.CheckLogDropped is incremented.
func (w *checkLogWriter) Enqueue(e *checklog.Entry) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.stopped {
		w.metrics.CheckLogDropped()
		return
	}
	select {
	case w.queue <- e:
	default:
		w.metrics.CheckLogDropped()
	}
}

func (w *checkLogWriter) run() {
	defer w.wg.Done()

	batch := make([]*checklog.Entry, 0, checkLogBatchSize)
	ticker := time.NewTicker(checkLogFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.writeBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-w.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= checkLogBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *checkLogWriter) writeBatch(batch []*checklog.Entry) {
	n := 0
	for _, e := range batch {
		if err := w.store.CreateCheckLog(context.Background(), e); err != nil {
			w.logger.Error("warden: failed to write check log entry", log.Error(err))
			continue
		}
		n++
	}
	if n > 0 {
		w.metrics.CheckLogWritten(n)
	}
}

// Stop signals the writer to drain its queue and stop, blocking until the
// writer goroutine exits or ctx is done, whichever comes first.
func (w *checkLogWriter) Stop(ctx context.Context) error {
	w.mu.Lock()
	if !w.stopped {
		w.stopped = true
		close(w.queue)
	}
	w.mu.Unlock()

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
