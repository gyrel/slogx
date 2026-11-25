package rotate

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

type operation struct {
	data []byte
	done chan error
}

// Async is a bounded best-effort writer. Writes never wait for queue capacity.
type Async struct {
	mu       sync.Mutex
	queue    []operation
	capacity int
	wake     *sync.Cond
	closed   bool
	dropped  atomic.Uint64
	done     chan struct{}
	w        io.Writer
	err      error
}

// NewAsync wraps w with a bounded queue. A nonpositive capacity makes every write overflow.
func NewAsync(w io.Writer, queueCap int) *Async {
	if queueCap < 0 {
		queueCap = 0
	}
	a := &Async{capacity: queueCap, done: make(chan struct{}), w: w}
	a.wake = sync.NewCond(&a.mu)
	go a.run()
	return a
}
func (a *Async) run() {
	defer close(a.done)
	for {
		a.mu.Lock()
		for len(a.queue) == 0 && !a.closed {
			a.wake.Wait()
		}
		if len(a.queue) == 0 && a.closed {
			a.mu.Unlock()
			return
		}
		op := a.queue[0]
		a.queue[0] = operation{}
		a.queue = a.queue[1:]
		a.mu.Unlock()
		if op.done != nil {
			if f, ok := a.w.(interface{ Flush() error }); ok {
				a.err = errors.Join(a.err, f.Flush())
			}
			op.done <- a.err
			continue
		}
		n, err := a.w.Write(op.data)
		if err == nil && n != len(op.data) {
			err = io.ErrShortWrite
		}
		a.err = errors.Join(a.err, err)
	}
}

// Write copies p and queues it, or drops it when the queue is full. Overflow is reported by Dropped.
func (a *Async) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, os.ErrClosed
	}
	data := append([]byte(nil), p...)
	if len(a.queue) >= a.capacity {
		a.dropped.Add(1)
	} else {
		a.queue = append(a.queue, operation{data: data})
		a.wake.Signal()
	}
	return len(p), nil
}

// Dropped atomically drains the number of records dropped since the previous call.
func (a *Async) Dropped() uint64 { return a.dropped.Swap(0) }

// Flush waits for all writes accepted before its barrier and flushes the underlying writer when supported.
func (a *Async) Flush() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return os.ErrClosed
	}
	done := make(chan error, 1)
	a.queue = append(a.queue, operation{done: done})
	a.wake.Signal()
	a.mu.Unlock()
	return <-done
}

// Close refuses new writes, drains the queue, and closes the underlying writer if supported.
func (a *Async) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return os.ErrClosed
	}
	a.closed = true
	a.wake.Signal()
	a.mu.Unlock()
	<-a.done
	err := a.err
	if f, ok := a.w.(interface{ Flush() error }); ok {
		err = errors.Join(err, f.Flush())
	}
	if c, ok := a.w.(io.Closer); ok {
		err = errors.Join(err, c.Close())
	}
	return err
}

// SyncDurable writes synchronously and flushes every record when supported.
type SyncDurable struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSyncDurable wraps a writer for synchronous audit records. The sink must provide Flush or Sync for durability.
func NewSyncDurable(w io.Writer) *SyncDurable { return &SyncDurable{w: w} }
func (s *SyncDurable) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	if f, ok := s.w.(interface{ Flush() error }); ok {
		return n, f.Flush()
	}
	if f, ok := s.w.(interface{ Sync() error }); ok {
		return n, f.Sync()
	}
	return n, errors.New("rotate: audit sink has no Flush or Sync")
}
