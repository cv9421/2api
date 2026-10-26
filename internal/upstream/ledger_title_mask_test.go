package upstream

import (
	"encoding/json"
	"testing"
)

// 标题遮罩：末尾追加一条固定内容 user 消息，其余消息逐字不动。
func TestAppendLedgerTitleMaskAppends(t *testing.T) {
	in := `{"model":"m","messages":[{"role":"system","content":"s"},{"role":"user","content":"机密问题"}]}`
	out := AppendLedgerTitleMask([]byte(in))
	var obj struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(obj.Messages) != 3 {
		t.Fatalf("messages=%d want 3", len(obj.Messages))
	}
	if obj.Messages[1]["content"] != "机密问题" {
		t.Errorf("原有消息被改写: %v", obj.Messages[1]["content"])
	}
	last := obj.Messages[2]
	if last["role"] != "user" || last["content"] != LedgerTitleMaskText {
		t.Errorf("末条=%v want user/%q", last, LedgerTitleMaskText)
	}
}

// tool 结尾的 agent 循环形态同样生效（标题本来会显示工具输出）。
func TestAppendLedgerTitleMaskAfterTool(t *testing.T) {
	in := `{"model":"m","messages":[{"role":"user","content":"q"},{"role":"tool","tool_call_id":"c1","content":"文件内容"}]}`
	out := AppendLedgerTitleMask([]byte(in))
	var obj struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n := len(obj.Messages); n != 3 || obj.Messages[2]["content"] != LedgerTitleMaskText {
		t.Fatalf("messages=%v want 末条为遮罩", obj.Messages)
	}
}

// 幂等：已是遮罩形态时不再叠加第二条。
func TestAppendLedgerTitleMaskIdempotent(t *testing.T) {
	in := `{"messages":[{"role":"user","content":"q"},{"role":"user","content":"` + LedgerTitleMaskText + `"}]}`
	out := AppendLedgerTitleMask([]byte(in))
	var obj struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(obj.Messages) != 2 {
		t.Fatalf("messages=%d want 2（幂等不应叠加）", len(obj.Messages))
	}
}

// 形态保护：非 JSON / 无 messages / messages 非数组 一律原样返回。
func TestAppendLedgerTitleMaskGuards(t *testing.T) {
	cases := []string{
		`not json`,
		`{"model":"m"}`,
		`{"model":"m","messages":"oops"}`,
		``,
	}
	for _, in := range cases {
		if got := string(AppendLedgerTitleMask([]byte(in))); got != in {
			t.Errorf("in=%q got=%q want 原样返回", in, got)
		}
	}
}

// 管线位置：prepareBody 的遮罩必须排在最后一条，且不改动 model / 其他顶层字段。
func TestPrepareBodyMaskKeepsTopLevel(t *testing.T) {
	c := New()
	c.HideLedgerTitle.Store(true)
	in := `{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"max_tokens":32}`
	out := c.prepareBody([]byte(in), "cn", "uid1", "conv-1")
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "glm-5.2" {
		t.Errorf("model=%v", obj["model"])
	}
	msgs, _ := obj["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages=%d want 2", len(msgs))
	}
	if last, _ := msgs[len(msgs)-1].(map[string]any); last["content"] != LedgerTitleMaskText {
		t.Errorf("末条=%v", last)
	}
	// 关掉后必须完全不加（默认行为零回归）。
	c.HideLedgerTitle.Store(false)
	out2 := c.prepareBody([]byte(in), "cn", "uid1", "conv-1")
	var obj2 map[string]any
	_ = json.Unmarshal(out2, &obj2)
	if msgs2, _ := obj2["messages"].([]any); len(msgs2) != 1 {
		t.Fatalf("关闭后 messages=%d want 1", len(msgs2))
	}
}
