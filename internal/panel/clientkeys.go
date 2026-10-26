// clientkeys.go 面板「客户端 Key」管理：读写 nginx 的 05-apikeys.conf。
//
// 两份实现合成一份的历史教训：
//  1. 早期 A/B 两把 key 只能 SSH 手改正则，改错一个字符就是全站 401；
//  2. 引入面板后，面板能改 key，但网关只认一个 api_key → 面板"保存成功"、
//     客户端却全量 401。
//
// 现在网关直接读这份文件做鉴权（internal/clientkeys.Store），面板保存后
// 强制网关重读并当场自检每把启用中的 key——「保存成功」等价于「能真的调用」，
// 自检不过则整份回滚。
package panel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/clientkeys"
)

// clientKey 是面板与网关共用的 key 结构（字段与 05-apikeys.conf 一一对应）。
type clientKey = clientkeys.Key

func (p *Panel) readClientKeys() ([]clientKey, error) {
	return clientkeys.ReadFile(p.cfg.ClientKeyFile)
}

func (p *Panel) renderClientKeys(keys []clientKey) string { return clientkeys.Render(keys) }

func dockerNginx(args ...string) error {
	cmd := exec.Command("docker", append([]string{"exec", "openresty", "nginx"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyClientKeys 落盘 → nginx 重载 → 网关重读 → 自检；任一步失败整份回滚。
//
// 自检是这次新增的关键一步：只有每把启用中的 key 都能通过网关鉴权，才认为
// 「保存成功」。否则会出现面板显示已保存、客户端却拿到 401 的割裂状态。
func (p *Panel) applyClientKeys(keys []clientKey) error {
	orig, err := os.ReadFile(p.cfg.ClientKeyFile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.cfg.ClientKeyFile, []byte(p.renderClientKeys(keys)), 0o644); err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = os.WriteFile(p.cfg.ClientKeyFile, orig, 0o644)
		_ = dockerNginx("-s", "reload")
		p.reloadGatewayKeys()
		return cause
	}
	if err := dockerNginx("-t"); err != nil {
		return rollback(fmt.Errorf("nginx -t 失败，已回滚：%v", err))
	}
	if err := dockerNginx("-s", "reload"); err != nil {
		return rollback(fmt.Errorf("reload 失败，已回滚：%v", err))
	}
	// 让网关立即重读（不依赖 mtime 精度/文件系统时间戳）。
	p.reloadGatewayKeys()
	if err := p.verifyClientKeys(keys); err != nil {
		return rollback(err)
	}
	return nil
}

func (p *Panel) reloadGatewayKeys() {
	if p.cfg.ReloadClientKeys != nil {
		p.cfg.ReloadClientKeys()
	}
}

// verifyClientKeys 用每把启用中的 key 直接打网关本地端口，确认鉴权放行。
//
// 只把 401 视为失败：其他状态码（200/503…）说明鉴权层已经过了，剩下的
// 是账号池/上游状态，不该把一次 key 保存判为失败。
// GatewayAddr 为空（非标准部署）时跳过自检，保持向后兼容。
func (p *Panel) verifyClientKeys(keys []clientKey) error {
	addr := strings.TrimSpace(p.cfg.GatewayAddr)
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	for _, k := range keys {
		if k.Disabled || strings.TrimSpace(k.Key) == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/status", nil)
		if err != nil {
			return fmt.Errorf("自检请求构造失败：%v", err)
		}
		req.Header.Set("Authorization", "Bearer "+k.Key)
		resp, err := cl.Do(req)
		if err != nil {
			return fmt.Errorf("自检失败（%s）：网关不可达 %v", k.ID, err)
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code == http.StatusUnauthorized {
			return fmt.Errorf("自检失败：key %s 被网关拒绝（401），已回滚", k.ID)
		}
	}
	return nil
}

func newClientKey() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	s := base64.RawURLEncoding.EncodeToString(buf)
	if len(s) > 24 {
		s = s[:24]
	}
	return "sk-" + s
}

func (p *Panel) apiClientKeys(w http.ResponseWriter, r *http.Request) {
	if p.cfg.ClientKeyFile == "" {
		writeErr(w, http.StatusNotImplemented, "client keys api not available")
		return
	}
	if r.Method == http.MethodGet {
		keys, err := p.readClientKeys()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取 key 文件失败："+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "keys": keys, "file": p.cfg.ClientKeyFile})
		return
	}

	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求失败："+err.Error())
		return
	}
	keys, err := p.readClientKeys()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch req.Action {
	case "rotate":
		found := false
		for i := range keys {
			if keys[i].ID == req.ID {
				keys[i].Key = newClientKey()
				found = true
			}
		}
		if !found {
			writeErr(w, http.StatusNotFound, "没有这个身份："+req.ID)
			return
		}
	case "set":
		k := strings.TrimSpace(req.Key)
		if !strings.HasPrefix(k, "sk-") || len(k) < 12 {
			writeErr(w, http.StatusBadRequest, "key 必须以 sk- 开头且不短于 12 字符")
			return
		}
		found := false
		for i := range keys {
			if keys[i].ID == req.ID {
				keys[i].Key = k
				found = true
			}
		}
		if !found {
			keys = append(keys, clientKey{ID: req.ID, Key: k})
		}
	case "disable", "enable":
		found := false
		for i := range keys {
			if keys[i].ID == req.ID {
				keys[i].Disabled = req.Action == "disable"
				found = true
			}
		}
		if !found {
			writeErr(w, http.StatusNotFound, "没有这个身份："+req.ID)
			return
		}
	case "delete":
		out := make([]clientKey, 0, len(keys))
		for _, k := range keys {
			if k.ID != req.ID {
				out = append(out, k)
			}
		}
		keys = out
	case "add":
		if strings.TrimSpace(req.ID) == "" {
			writeErr(w, http.StatusBadRequest, "身份不能为空")
			return
		}
		keys = append(keys, clientKey{ID: strings.TrimSpace(req.ID), Key: newClientKey()})
	default:
		writeErr(w, http.StatusBadRequest, "未知动作："+req.Action)
		return
	}

	if err := p.applyClientKeys(keys); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "keys": keys})
}
