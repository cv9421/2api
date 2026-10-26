// monitor.go 面板「API 监控」接口：读 api_monitor.jsonl（外部探测器每分钟写入）
// 现算窗口统计，前端只负责渲染。
//
// 为什么不让前端自己算：JSONL 里一小时就是 180 条、一天 4300 条，全丢给浏览器
// 解析既慢又容易被大文件噎住；现算现返，面板只拿到聚合结果 + 最近 60 条明细。
package panel

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

// monitorPoint 是探测器写入的一行（api_monitor.py）。
type monitorPoint struct {
	TS     string `json:"ts"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Code   int    `json:"code"`
	MS     int    `json:"ms"`
	Detail string `json:"detail"`
}

// monitorCheck 是单个检查项的窗口聚合。
type monitorCheck struct {
	Name   string        `json:"name"`
	Count  int           `json:"count"`
	OKRate int           `json:"ok_rate"`
	P50    int           `json:"p50"`
	P95    int           `json:"p95"`
	Max    int           `json:"max"`
	Last   *monitorPoint `json:"last"`
}

// apiMonitor GET /panel/api/apimonitor?hours=24
func (p *Panel) apiMonitor(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	resp := map[string]any{
		"ok":           true,
		"window_hours": hours,
		"checks":       []monitorCheck{},
		"recent":       []monitorPoint{},
	}
	if p.cfg.MonitorFile == "" {
		resp["note"] = "未配置监控数据文件（panel.monitor_file）"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	f, err := os.Open(p.cfg.MonitorFile)
	if err != nil {
		resp["note"] = "还没有探测数据（探测器尚未跑过）"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	defer f.Close()

	cut := time.Now().Add(-time.Duration(hours) * time.Hour)
	var pts []monitorPoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var pt monitorPoint
		if json.Unmarshal(sc.Bytes(), &pt) != nil {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", pt.TS, time.Local)
		if err != nil || t.Before(cut) {
			continue
		}
		pts = append(pts, pt)
	}

	order := []string{}
	group := map[string][]monitorPoint{}
	for _, pt := range pts {
		if _, seen := group[pt.Name]; !seen {
			order = append(order, pt.Name)
		}
		group[pt.Name] = append(group[pt.Name], pt)
	}
	checks := make([]monitorCheck, 0, len(order))
	for _, name := range order {
		v := group[name]
		lat := make([]int, 0, len(v))
		okCount := 0
		for _, x := range v {
			lat = append(lat, x.MS)
			if x.OK {
				okCount++
			}
		}
		sort.Ints(lat)
		p50 := lat[len(lat)/2]
		p95 := lat[len(lat)-1]
		if n := int(float64(len(lat)) * 0.95); n < len(lat) {
			p95 = lat[n]
		}
		last := v[len(v)-1]
		checks = append(checks, monitorCheck{
			Name:   name,
			Count:  len(v),
			OKRate: okCount * 100 / len(v),
			P50:    p50,
			P95:    p95,
			Max:    lat[len(lat)-1],
			Last:   &last,
		})
	}
	resp["checks"] = checks

	recent := []monitorPoint{}
	for i := len(pts) - 1; i >= 0 && len(recent) < 60; i-- {
		recent = append(recent, pts[i])
	}
	resp["recent"] = recent
	writeJSON(w, http.StatusOK, resp)
}
