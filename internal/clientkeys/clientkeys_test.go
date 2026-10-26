package clientkeys

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Key
		ok   bool
	}{
		{"normal", `    "~*^Bearer\s+sk-abc$" "A";`, Key{ID: "A", Key: "sk-abc"}, true},
		{"disabled", `    #disabled "~*^Bearer\s+sk-abc$" "B";`, Key{ID: "B", Key: "sk-abc", Disabled: true}, true},
		{"comment", "# 客户端 key → 身份", Key{}, false},
		{"map-open", "map $http_authorization $client_id {", Key{}, false},
		{"default", `    default "";`, Key{}, false},
		{"garbage", "hello world", Key{}, false},
		{"no-dollar", `"~*^Bearer\s+sk-abc" "A";`, Key{}, false},
	}
	for _, c := range cases {
		got, ok := ParseLine(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got=%+v ok=%v want=%+v ok=%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestRenderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "05-apikeys.conf")
	in := []Key{{ID: "A", Key: "sk-aaa"}, {ID: "B", Key: "sk-bbb", Disabled: true}}
	if err := os.WriteFile(fp, []byte(Render(in)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(fp)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("roundtrip=%+v want %+v", got, in)
	}
}

func TestReadFileMissingIsEmpty(t *testing.T) {
	keys, err := ReadFile(filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil || keys != nil {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
}

func TestFind(t *testing.T) {
	keys := []Key{{ID: "A", Key: "sk-aaa"}, {ID: "B", Key: "sk-bbb", Disabled: true}}
	if k, ok := Find(keys, "sk-aaa"); !ok || k.ID != "A" {
		t.Errorf("sk-aaa: %+v %v", k, ok)
	}
	if _, ok := Find(keys, "sk-bbb"); ok {
		t.Error("disabled key must not match")
	}
	if _, ok := Find(keys, ""); ok {
		t.Error("empty token must not match")
	}
}

func TestExtractBearer(t *testing.T) {
	if got := ExtractBearer("Bearer sk-x"); got != "sk-x" {
		t.Errorf("got %q", got)
	}
	if got := ExtractBearer("Basic abc"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "05-apikeys.conf")
	write := func(keys []Key) {
		t.Helper()
		if err := os.WriteFile(fp, []byte(Render(keys)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write([]Key{{ID: "A", Key: "sk-aaa"}})
	s := NewStore(fp)
	if k, ok := s.Lookup("sk-aaa"); !ok || k.ID != "A" {
		t.Fatalf("initial lookup failed: %+v %v", k, ok)
	}

	// 轮换：旧 key 立即失效、新 key 立即可用（不重启、不显式 Reload）
	time.Sleep(5 * time.Millisecond)
	write([]Key{{ID: "A", Key: "sk-rot"}})
	if _, ok := s.Lookup("sk-aaa"); ok {
		t.Error("old key still accepted after rotation")
	}
	if k, ok := s.Lookup("sk-rot"); !ok || k.ID != "A" {
		t.Fatalf("rotated key not accepted: %+v %v", k, ok)
	}

	// 文件删除：退化为空清单，不 panic
	if err := os.Remove(fp); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup("sk-rot"); ok {
		t.Error("key still accepted after file removal")
	}
	if got := NewStore("").Keys(); got != nil {
		t.Errorf("empty path store should be nil, got %v", got)
	}
}
