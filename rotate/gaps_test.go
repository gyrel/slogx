package rotate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPreexistingArchivesPruned(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	for i := 1; i <= 9; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", p, i), []byte(fmt.Sprint(i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := New(p, Config{MaxSizeBytes: 1, MaxFiles: 5, TotalCapBytes: 6})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 9; i++ {
		b, err := os.ReadFile(fmt.Sprintf("%s.%d", p, i))
		if i <= 5 {
			want := "a"
			if i > 1 {
				want = fmt.Sprint(i - 1)
			}
			if err != nil || string(b) != want {
				t.Fatalf("archive %d: %q %v", i, b, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archive %d: %v", i, err)
		}
	}
}

func TestAsyncFlushDoesNotBlockWrites(t *testing.T) {
	b := &blocked{start: make(chan struct{}), release: make(chan struct{})}
	a := NewAsync(b, 1)
	_, _ = a.Write([]byte("a"))
	<-b.start
	_, _ = a.Write([]byte("b"))
	flushed := make(chan error, 1)
	go func() { flushed <- a.Flush() }()
	// Wait until the flush barrier is queued while the sink is blocked.
	deadline := time.After(time.Second)
	for {
		a.mu.Lock()
		n := len(a.queue)
		a.mu.Unlock()
		if n == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("flush did not queue")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	wrote := make(chan error, 1)
	go func() { _, err := a.Write([]byte("c")); wrote <- err }()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write blocked during flush")
	}
	if n := a.Dropped(); n != 1 {
		t.Fatalf("dropped %d", n)
	}
	close(b.release)
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if b.b.String() != "ab" {
		t.Fatalf("records %q", b.b.String())
	}
	if _, err := a.Write(nil); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err := a.Flush(); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRenameFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string
	}{{"first failure", []string{"b"}}, {"sticky failure", []string{"b", "c"}}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "app.log")
			w, err := New(p, Config{MaxSizeBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write([]byte("a")); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(dir, 0500); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(dir, 0700)
			// Privileged users can bypass directory permissions; do not claim this exercises failure.
			probe := filepath.Join(dir, "probe")
			if err = os.WriteFile(probe, nil, 0600); err == nil {
				_ = os.Remove(probe)
				_ = w.Close()
				t.Skip("directory permissions bypassed")
			}
			for _, s := range tc.writes {
				if _, err = w.Write([]byte(s)); err == nil {
					t.Fatal("expected rotation error")
				}
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(p)
			if err != nil || string(b) != "a"+joinWrites(tc.writes) {
				t.Fatalf("contents %q: %v", b, err)
			}
		})
	}
}
func joinWrites(ss []string) string {
	var s string
	for _, v := range ss {
		s += v
	}
	return s
}

func TestAsyncCloseRefusesWhileDraining(t *testing.T) {
	b := &blocked{start: make(chan struct{}), release: make(chan struct{})}
	a := NewAsync(b, 1)
	_, _ = a.Write([]byte("a"))
	<-b.start
	_, _ = a.Write([]byte("b"))
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	deadline := time.After(time.Second)
	for {
		a.mu.Lock()
		closing := a.closed
		a.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("close did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := a.Write([]byte("c")); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	close(b.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if b.b.String() != "ab" {
		t.Fatalf("records %q", b.b.String())
	}
}
