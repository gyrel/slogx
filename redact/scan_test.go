package redact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

func TestCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/canaries.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("bad corpus row %q", line)
		}
		t.Run(parts[0], func(t *testing.T) {
			found := Scan([]byte(parts[1]), Options{HomeUser: "alice"})
			ok := false
			for _, v := range found {
				if v.Rule == parts[0] {
					ok = true
				}
				if !v.NoValue {
					t.Fatal("missing NoValue")
				}
			}
			if !ok {
				t.Errorf("rule %s not found: %+v", parts[0], found)
			}
			if got := Scan([]byte(parts[2]), Options{HomeUser: "alice"}); len(got) != 0 {
				t.Errorf("negative control: %+v", got)
			}
		})
	}
}
func TestBenign(t *testing.T) {
	data, err := os.ReadFile("testdata/benign.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if got := Scan(data, Options{}); len(got) > 0 {
		t.Fatal(got)
	}
}
func TestBundleGuard(t *testing.T) {
	for _, format := range []string{"zip", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if format == "zip" {
				w := zip.NewWriter(&b)
				f, e := w.Create("logs/a")
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write([]byte("password=canary")); e != nil {
					t.Fatal(e)
				}
				if e = w.Close(); e != nil {
					t.Fatal(e)
				}
			} else {
				gz := gzip.NewWriter(&b)
				w := tar.NewWriter(gz)
				s := "password=canary"
				if e := w.WriteHeader(&tar.Header{Name: "logs/a", Mode: 0600, Size: int64(len(s))}); e != nil {
					t.Fatal(e)
				}
				if _, e := w.Write([]byte(s)); e != nil {
					t.Fatal(e)
				}
				if e := w.Close(); e != nil {
					t.Fatal(e)
				}
				if e := gz.Close(); e != nil {
					t.Fatal(e)
				}
			}
			v, stats, e := BundleGuard(&b, Options{})
			if e != nil || len(v) != 1 || len(stats) != 1 || v[0].Path != "logs/a" || stats[0].Violations != 1 {
				t.Fatalf("%+v %+v %v", v, stats, e)
			}
		})
	}
}
func FuzzScan(f *testing.F) {
	f.Add([]byte("password=canary"))
	f.Add([]byte{0xff, 0, 0xfe})
	f.Fuzz(func(t *testing.T, b []byte) { Scan(b, Options{}) })
}
