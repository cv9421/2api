// Package clientkeys 管理「客户端 key → 身份标签」映射文件（nginx 05-apikeys.conf）。
//
// 同一份文件三方共用：面板负责写（新增/轮换/删除），nginx 用它的 map 给 /v1/ 访问
// 日志打身份标签，wb2api 用它做真正的 Bearer 鉴权。
//
// 之所以要由网关自己认这份文件：曾经「面板改 key、nginx 换标签、网关却只认一个
// api_key」，面板轮换之后新 key 根本过不了鉴权，客户端全量 401，而面板上一切正常。
// 把鉴权收敛到这份文件后，面板保存 = 立即生效，不再有第二份白名单可以漂移。
package clientkeys

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"os"
	"strings"
	"sync"
	"time"
)

// Key 是一把客户端 key 及其身份标签。
type Key struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	// Disabled 为真时，该行在文件里是注释状态（#disabled 前缀）：key 值保留，
	// 但既不参与鉴权，也不参与 nginx 的日志打标，随时能启用回来。
	Disabled bool `json:"disabled"`
}

// 用 rune 常量拼引号与反斜杠，避免源码里出现转义序列（踩过的坑：源码里的 \n
// 被当成真换行写进字符串，Go 直接编译不过）。
const (
	quote  = string(rune(34))
	bslash = string(rune(92))
	bearer = "Bearer "
)

// ParseLine 解析一行 map 条目：
//
//	"~*^Bearer\s+sk-xxx$" "A";
func ParseLine(line string) (Key, bool) {
	l := strings.TrimSpace(line)
	if l == "" {
		return Key{}, false
	}
	disabled := false
	if strings.HasPrefix(l, "#disabled") {
		disabled = true
		l = strings.TrimSpace(strings.TrimPrefix(l, "#disabled"))
	} else if strings.HasPrefix(l, "#") {
		return Key{}, false // 普通注释行
	}
	i := strings.Index(l, "Bearer")
	if i < 0 {
		return Key{}, false
	}
	rest := l[i+len("Bearer"):]
	if len(rest) < 4 {
		return Key{}, false
	}
	rest = rest[3:] // 跳过 \s+
	j := strings.Index(rest, "$")
	if j < 0 {
		return Key{}, false
	}
	key := rest[:j]
	parts := strings.Split(rest[j:], quote)
	if len(parts) < 4 || strings.TrimSpace(parts[2]) == "" {
		return Key{}, false
	}
	return Key{ID: strings.TrimSpace(parts[2]), Key: key, Disabled: disabled}, true
}

// ReadFile 读取整份映射文件。文件不存在视为空清单：网关允许在没有该文件的机器上
// 以「只认 api_key」的模式运行。
func ReadFile(path string) ([]Key, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	out := []Key{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, ok := ParseLine(sc.Text()); ok {
			out = append(out, k)
		}
	}
	return out, sc.Err()
}

// Render 把清单渲染成 nginx map 文件内容（面板保存时调用）。
func Render(keys []Key) string {
	var b strings.Builder
	b.WriteString("# 客户端 key → 身份（面板「安全监控 → 客户端 Key」可改）\n")
	b.WriteString("# 必须排在 00-hash-tuning.conf 之后：map 不能早于 map_hash_bucket_size。\n")
	b.WriteString("# 网关（wb2api）直接读这份文件做鉴权，改完即生效，无需再改别处。\n")
	b.WriteString("map $http_authorization $client_id {\n")
	b.WriteString("    default " + quote + quote + ";\n")
	for _, k := range keys {
		prefix := "    "
		if k.Disabled {
			prefix = "    #disabled " // 整行注释 = 该 key 不参与匹配
		}
		b.WriteString(prefix + quote + "~*^Bearer" + bslash + "s+" + k.Key + "$" + quote + " " + quote + k.ID + quote + ";\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// ExtractBearer 取出 Authorization 头里的 token；方案不是 Bearer 时返回空串。
func ExtractBearer(authz string) string {
	if !strings.HasPrefix(authz, bearer) {
		return ""
	}
	return strings.TrimSpace(authz[len(bearer):])
}

// Find 在清单里查 token。用摘要 + 常量时间比较，且遍历全程不提前返回：
// 命中与否不体现在耗时形状上。
func Find(keys []Key, token string) (Key, bool) {
	if token == "" {
		return Key{}, false
	}
	want := digest(token)
	var hit Key
	found := false
	for _, k := range keys {
		equal := subtle.ConstantTimeCompare(digest(k.Key), want) == 1
		if equal && !k.Disabled && !found {
			hit, found = k, true
		}
	}
	return hit, found
}

func digest(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// Store 是映射文件的热加载视图：按 mtime+size 判断是否变更，变更即重读。
// 面板保存后会额外调一次 Reload，保证「保存完成」与「可鉴权」之间没有窗口。
type Store struct {
	path string

	mu    sync.Mutex
	keys  []Key
	mtime time.Time
	size  int64
	seen  bool
}

// NewStore 创建热加载存储；path 为空时 Keys 恒为空（等价于只认 api_key）。
func NewStore(path string) *Store { return &Store{path: path} }

// Keys 返回当前清单（必要时重读文件）。
func (s *Store) Keys() []Key {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
	return s.keys
}

// Lookup 查 token 对应的客户端身份。
func (s *Store) Lookup(token string) (Key, bool) {
	return Find(s.Keys(), token)
}

// Reload 强制重读文件（供面板保存后调用）。
func (s *Store) Reload() {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = false
	s.reloadLocked()
}

func (s *Store) reloadLocked() {
	fi, err := os.Stat(s.path)
	if err != nil {
		s.keys, s.mtime, s.size, s.seen = nil, time.Time{}, 0, true
		return
	}
	if s.seen && fi.ModTime().Equal(s.mtime) && fi.Size() == s.size {
		return
	}
	keys, err := ReadFile(s.path)
	if err != nil {
		return // 读失败保留上一份，避免瞬时 IO 错误把所有人踢下线
	}
	s.keys, s.mtime, s.size, s.seen = keys, fi.ModTime(), fi.Size(), true
}
