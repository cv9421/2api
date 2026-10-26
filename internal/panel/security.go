// security.go 面板「安全监控」接口。
//
// 数据源切换（重要）：引入 one-api 之后，wb2api 看到的对端永远是 127.0.0.1，
// request-logs 里的来源 IP 全部失真。真实来源只有边缘层 nginx 知道，所以这里
// 改成解析 nginx 的 /v1/ 访问日志（v1.log，格式见 00-logformat.conf）。
// token 总量仍从 request-logs 的 JSONL 累加（那份与来源无关，依然准确）。
package panel

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// 新版 v1.log：time ip "cid" status rt "ua"；旧版无引号，解析直接跳过。
var reEdge = regexp.MustCompile("^(\\S+) (\\S+) \"([^\"]*)\" (\\d{3}) ([0-9.]+) \"(.*)\"$")

type sourceRow struct {
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	ClientID  string `json:"client_id"`
	Requests  int    `json:"requests"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	IsNew     bool   `json:"is_new"`
}

type keyRow struct {
	ID        string `json:"id"`
	Requests  int    `json:"requests"`
	Sources   int    `json:"sources"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type authFail struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	KeyPfx string `json:"key_prefix"`
}

func (p *Panel) apiSecurity(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}
	resp := map[string]any{
		"ok": true, "window_hours": hours,
		"totals": map[string]any{}, "sources": []sourceRow{}, "keys": []keyRow{},
		"auth_fails": []authFail{}, "hourly": []map[string]any{},
		"new_ips": []string{},
	}
	cut := time.Now().Add(-time.Duration(hours) * time.Hour)
	baseHour := time.Now().Truncate(time.Hour)

	hourly := make([]map[string]any, hours)
	for i := 0; i < hours; i++ {
		start := baseHour.Add(-time.Duration(hours-1-i) * time.Hour)
		hourly[i] = map[string]any{"t": start.Format("15:04"), "req": 0, "fail": 0, "tok": 0}
	}

	type agg struct {
		requests     int
		ua, cid      string
		first, last  time.Time
	}
	byIP := map[string]*agg{}
	type kagg struct {
		requests    int
		ips         map[string]bool
		first, last time.Time
	}
	byKey := map[string]*kagg{}
	var fails []authFail
	totalReq := 0

	if f, err := os.Open(p.cfg.EdgeLogFile); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			m := reEdge.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			t, err := time.Parse(time.RFC3339, m[1])
			if err != nil || t.Before(cut) {
				continue
			}
			ip, cid, ua := m[2], m[3], m[6]
			status, _ := strconv.Atoi(m[4])
			totalReq++

			if a := byIP[ip]; a == nil {
				byIP[ip] = &agg{requests: 1, ua: ua, cid: cid, first: t, last: t}
			} else {
				a.requests++
				if t.After(a.last) {
					a.last, a.ua, a.cid = t, ua, cid
				}
				if t.Before(a.first) {
					a.first = t
				}
			}
			kid := cid
			if kid == "" {
				kid = "未标注"
			}
			if k := byKey[kid]; k == nil {
				byKey[kid] = &kagg{requests: 1, ips: map[string]bool{ip: true}, first: t, last: t}
			} else {
				k.requests++
				k.ips[ip] = true
				if t.After(k.last) {
					k.last = t
				}
				if t.Before(k.first) {
					k.first = t
				}
			}
			if status == http.StatusUnauthorized {
				fails = append(fails, authFail{Time: t.Format("2006-01-02 15:04:05"), IP: ip, UA: ua, KeyPfx: cid})
			}
			idx := int(baseHour.Sub(t.Truncate(time.Hour)) / time.Hour)
			if idx >= 0 && idx < hours {
				b := hourly[hours-1-idx]
				b["req"] = b["req"].(int) + 1
				if status == http.StatusUnauthorized {
					b["fail"] = b["fail"].(int) + 1
				}
			}
		}
		f.Close()
	} else {
		resp["note"] = "边缘日志不可读：" + p.cfg.EdgeLogFile
	}

	// token 总量：与来源无关，仍从 request-logs 累加
	totalTok := 0
	if p.cfg.RequestLogDir != "" {
		if entries, err := os.ReadDir(p.cfg.RequestLogDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				f, err := os.Open(p.cfg.RequestLogDir + "/" + e.Name())
				if err != nil {
					continue
				}
				sc := bufio.NewScanner(f)
				sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
				for sc.Scan() {
					var d struct {
						Time        string `json:"time"`
						TotalTokens int    `json:"total_tokens"`
					}
					if json.Unmarshal(sc.Bytes(), &d) != nil {
						continue
					}
					t, err := time.Parse(time.RFC3339Nano, d.Time)
					if err == nil && !t.Before(cut) {
						totalTok += d.TotalTokens
					}
				}
				f.Close()
			}
		}
	}

	rows := make([]sourceRow, 0, len(byIP))
	for ip, a := range byIP {
		rows = append(rows, sourceRow{
			IP: ip, UA: a.ua, ClientID: a.cid, Requests: a.requests,
			FirstSeen: a.first.Format("2006-01-02 15:04:05"),
			LastSeen:  a.last.Format("2006-01-02 15:04:05"),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Requests > rows[j].Requests })
	if len(rows) > 30 {
		rows = rows[:30]
	}
	keys := make([]keyRow, 0, len(byKey))
	for id, k := range byKey {
		keys = append(keys, keyRow{
			ID: id, Requests: k.requests, Sources: len(k.ips),
			FirstSeen: k.first.Format("2006-01-02 15:04:05"),
			LastSeen:  k.last.Format("2006-01-02 15:04:05"),
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Requests > keys[j].Requests })
	sort.Slice(fails, func(i, j int) bool { return fails[i].Time > fails[j].Time })
	if len(fails) > 50 {
		fails = fails[:50]
	}

	resp["totals"] = map[string]any{
		"requests": totalReq, "tokens": totalTok,
		"sources": len(byIP), "auth_fails": len(fails),
	}
	resp["sources"] = rows
	resp["keys"] = keys
	resp["auth_fails"] = fails
	resp["hourly"] = hourly
	writeJSON(w, http.StatusOK, resp)
}
