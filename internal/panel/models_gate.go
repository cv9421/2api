// models_gate.go 面板「模型与档位」里的逐模型隐藏开关（fork 版，A1）。
//
// 落点选择：状态写在 config.json 的 models.hidden 里，与网关侧
// livecfg.NormalizeHiddenModels / Snapshot.HiddenModels 共用同一份真相——
// 面板上的开关、手改 config.json、网关的 /v1/models 过滤与点名拒绝，
// 三条路径看到的东西永远一致，不存在第二份状态可以漂移。
//
// 隐藏语义继承上游（不要另造一套）：
//   - 裸名 "x"          → cn 与 global 两域都隐藏
//   - "cn:x" / "global:x" → 只隐藏该域
//
// 写回时统一展开成带前缀的精确形式：裸名会被 Normalize 展开成两条，
// 直接按前缀写回可以让「面板上点的是哪一行」和「配置里存的是哪一条」一一对应。
package panel

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

// gateConfigMap 读取当前配置的通用 JSON 视图（不依赖 cmd/server 的具体类型）。
func (p *Panel) gateConfigMap() (map[string]any, error) {
	cfgAny, err := p.cfg.LoadConfig()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cfgAny)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// hiddenFromConfig 从配置 map 里取 models.hidden 原始列表。
func hiddenFromConfig(m map[string]any) []string {
	sec, _ := m["models"].(map[string]any)
	if sec == nil {
		return nil
	}
	raw, _ := sec["hidden"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// hiddenList 当前隐藏条目（读失败按「未隐藏」处理：面板只读视图不该因配置读失败整体 500）。
func (p *Panel) hiddenList() []string {
	if p.cfg.LoadConfig == nil {
		return nil
	}
	m, err := p.gateConfigMap()
	if err != nil {
		return nil
	}
	return hiddenFromConfig(m)
}

// hiddenQuerySet 归一化后的精确集合（"cn:x"/"global:x"），用于判断某一行当前是否隐藏。
func (p *Panel) hiddenQuerySet() map[string]struct{} {
	return livecfg.NormalizeHiddenModels(p.hiddenList())
}

// canonicalModelID 把面板传进来的 id 归一成带域前缀的形式。
// 列表页给的本来就是 "cn:x"，这里只兜底裸名（按 cn 处理，与面板行语义一致）。
func canonicalModelID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if prefix, bare, ok := strings.Cut(id, ":"); ok && (prefix == "cn" || prefix == "global") && bare != "" {
		return prefix + ":" + bare
	}
	return "cn:" + id
}

// gateInfo 面板渲染开关所需的能力自述 + 当前集合。
// toggle=true 表示本二进制真的能改；config_key 告诉用户手改配置时该动哪个键。
func (p *Panel) gateInfo() map[string]any {
	list := p.hiddenList()
	if list == nil {
		list = []string{}
	}
	return map[string]any{
		"toggle":     p.cfg.LoadConfig != nil && p.cfg.SaveConfig != nil,
		"config_key": "hidden",
		"hidden":     list,
	}
}

// modelToggle 翻转单个模型的隐藏开关。
//
// 请求体：{"id":"cn:glm-5.3","hidden":true}；hidden 省略时按当前状态取反。
// 兼容旧字段名 disabled（本地早期实现用的就是它），两个名字都收。
func (p *Panel) modelToggle(w http.ResponseWriter, r *http.Request) {
	if p.cfg.LoadConfig == nil || p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		ID       string `json:"id"`
		Hidden   *bool  `json:"hidden"`
		Disabled *bool  `json:"disabled"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "parse body: "+err.Error())
		return
	}
	id := canonicalModelID(req.ID)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少模型 id")
		return
	}

	m, err := p.gateConfigMap()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}

	// 当前集合：把裸名展开后的精确形式作为基底，增删都在这个基底上做。
	set := map[string]bool{}
	for k := range livecfg.NormalizeHiddenModels(hiddenFromConfig(m)) {
		set[k] = true
	}
	next := !set[id]
	if req.Hidden != nil {
		next = *req.Hidden
	} else if req.Disabled != nil {
		next = *req.Disabled
	}
	if next {
		set[id] = true
	} else {
		delete(set, id)
	}

	// 写回一律用带前缀的精确形式，排序后落盘（手改 diff 友好）。
	ids := make([]string, 0, len(set))
	for k := range set {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	sec, _ := m["models"].(map[string]any)
	if sec == nil {
		sec = map[string]any{}
		m["models"] = sec
	}
	sec["hidden"] = ids

	out, err := json.Marshal(m)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal config: "+err.Error())
		return
	}
	// SaveConfig 闭包内部完成：校验 → 深合并落盘（保留未知键）→ 热应用。
	// 这里刻意不回传 restart_required：models.hidden 走 livecfg 快照热生效，
	// 回传只会让用户误以为刚改的开关要重启。
	if _, err := p.cfg.SaveConfig(out); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	state := "放行"
	if next {
		state = "隐藏"
	}
	log.Printf("panel: 模型 %s → %s（当前共隐藏 %d 个）", id, state, len(ids))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"id":            id,
		"hidden":        next,
		"disabled":      next, // 旧字段名同义回传，前端两版都能读
		"hidden_models": ids,
	})
}
