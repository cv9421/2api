package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/clientkeys"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// TestClientKeyAuth 锁定「面板改完 key，网关立即认」这条契约：
//   - 文件里启用的 key 可通过鉴权；
//   - 轮换后新 key 立即可用、旧 key 立即失效（不重启、不显式 reload）；
//   - 禁用/删除即失效；
//   - api_key 仍然有效（面板自身与运维直连不能被误伤）；
//   - 未知 key 返回 401。
func TestClientKeyAuth(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "05-apikeys.conf")
	write := func(keys []clientkeys.Key) {
		t.Helper()
		if err := os.WriteFile(fp, []byte(clientkeys.Render(keys)), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // 确保 mtime 变化（同秒内多次写入）
	}
	write([]clientkeys.Key{{ID: "A", Key: "sk-aaa"}})

	h := NewHandler(Config{
		Pool:       testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at", ExpiresAt: 9999999999}),
		Upstream:   upstream.New(),
		APIKey:     "secret",
		ClientKeys: clientkeys.NewStore(fp),
	})
	code := func(token string) int {
		req := httptest.NewRequest("GET", "/v1/models", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := code("sk-aaa"); got != 200 {
		t.Fatalf("client key: code=%d want 200", got)
	}
	if got := code("secret"); got != 200 {
		t.Fatalf("api_key: code=%d want 200", got)
	}
	if got := code("sk-bogus"); got != 401 {
		t.Fatalf("bogus key: code=%d want 401", got)
	}
	if got := code(""); got != 401 {
		t.Fatalf("no key: code=%d want 401", got)
	}

	// 面板轮换：新值立即可用，旧值立即失效。
	write([]clientkeys.Key{{ID: "A", Key: "sk-rotated"}})
	if got := code("sk-rotated"); got != 200 {
		t.Fatalf("rotated key: code=%d want 200", got)
	}
	if got := code("sk-aaa"); got != 401 {
		t.Fatalf("old key after rotation: code=%d want 401", got)
	}

	// 面板禁用：立即失效；api_key 不受影响。
	write([]clientkeys.Key{{ID: "A", Key: "sk-rotated", Disabled: true}})
	if got := code("sk-rotated"); got != 401 {
		t.Fatalf("disabled key: code=%d want 401", got)
	}
	if got := code("secret"); got != 200 {
		t.Fatalf("api_key after disable: code=%d want 200", got)
	}

	// 面板删除：key 文件为空，客户端 key 全部失效。
	write(nil)
	if got := code("sk-rotated"); got != 401 {
		t.Fatalf("deleted key: code=%d want 401", got)
	}
}
