package rotate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRotationBoundaries(t *testing.T) {
	for _, n := range []int{3, 4, 5} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "app.log")
			w, e := New(p, Config{MaxSizeBytes: 4, MaxFiles: 2, TotalCapBytes: 100})
			if e != nil {
				t.Fatal(e)
			}
			_, _ = w.Write([]byte("a"))
			_, e = w.Write(bytes.Repeat([]byte("b"), n))
			if e != nil {
				t.Fatal(e)
			}
			_ = w.Close()
			_, e = os.Stat(p + ".1")
			if (e == nil) != (n > 3) {
				t.Fatalf("archive error: %v", e)
			}
		})
	}
}
func TestCapEvictsOldest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	w, e := New(p, Config{MaxSizeBytes: 2, MaxFiles: 4, TotalCapBytes: 4})
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"aa", "bb", "cc"} {
		if _, e = w.Write([]byte(s)); e != nil {
			t.Fatal(e)
		}
	}
	_ = w.Close()
	b, e := os.ReadFile(p + ".1")
	if e != nil || string(b) != "bb" {
		t.Fatalf("%s %v", b, e)
	}
	if _, e = os.Stat(p + ".2"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
func TestRotationFailureKeepsWriting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	w, e := New(p, Config{MaxSizeBytes: 1})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = w.Write([]byte("a"))
	if e = os.WriteFile(p+".rotate-tmp", nil, 0600); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"b", "c"} {
		if _, e = w.Write([]byte(s)); e == nil {
			t.Fatal("expected error")
		}
	}
	_ = w.Close()
	b, _ := os.ReadFile(p)
	if string(b) != "abc" {
		t.Fatal(string(b))
	}
}

type blocked struct {
	start   chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	b       bytes.Buffer
}

func (b *blocked) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.start); <-b.release })
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func TestAsyncOverflowAndFlush(t *testing.T) {
	b := &blocked{start: make(chan struct{}), release: make(chan struct{})}
	a := NewAsync(b, 1)
	_, _ = a.Write([]byte("a"))
	<-b.start
	_, _ = a.Write([]byte("b"))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = a.Write([]byte("x")) }()
	}
	wg.Wait()
	if n := a.Dropped(); n != 50 {
		t.Fatal(n)
	}
	if a.Dropped() != 0 {
		t.Fatal("counter not drained")
	}
	close(b.release)
	if e := a.Flush(); e != nil {
		t.Fatal(e)
	}
	if e := a.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Write(nil); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if b.b.String() != "ab" {
		t.Fatal(b.b.String())
	}
}

type failFlush struct{ bytes.Buffer }

func (*failFlush) Flush() error { return errors.New("flush") }
func TestSyncDurableError(t *testing.T) {
	s := NewSyncDurable(&failFlush{})
	if _, e := s.Write([]byte("x")); e == nil {
		t.Fatal("missing error")
	}
}
func FuzzParseChain(f *testing.F) {
	for _, s := range []string{"app.log.1", "app.log.01", "app.log.-1", "app.log.999999999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := parseChain(s, "app.log")
		if ok && (n <= 0 || s != fmt.Sprintf("app.log.%d", n)) {
			t.Fatalf("invalid: %q", s)
		}
	})
}
