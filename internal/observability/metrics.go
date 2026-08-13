package observability

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Metrics is a small dependency-free Prometheus collector. Callers supply only
// bounded labels; it never accepts tenant, request, rule, or content values.
type Metrics struct {
	mu         sync.Mutex
	counters   map[string]map[string]uint64
	histograms map[string]map[string]*histogram
	gauges     map[string]map[string]float64
}
type histogram struct {
	count   uint64
	sum     float64
	buckets []uint64
}

var latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2, 5}

func NewMetrics() *Metrics {
	return &Metrics{counters: map[string]map[string]uint64{}, histograms: map[string]map[string]*histogram{}, gauges: map[string]map[string]float64{}}
}
func (m *Metrics) Set(name string, value float64, labels map[string]string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := labelKey(labels)
	if m.gauges[name] == nil {
		m.gauges[name] = map[string]float64{}
	}
	m.gauges[name][key] = value
}
func (m *Metrics) Inc(name string, labels map[string]string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := labelKey(labels)
	if m.counters[name] == nil {
		m.counters[name] = map[string]uint64{}
	}
	m.counters[name][key]++
}
func (m *Metrics) Observe(name string, seconds float64, labels map[string]string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := labelKey(labels)
	if m.histograms[name] == nil {
		m.histograms[name] = map[string]*histogram{}
	}
	h := m.histograms[name][key]
	if h == nil {
		h = &histogram{buckets: make([]uint64, len(latencyBuckets))}
		m.histograms[name][key] = h
	}
	h.count++
	h.sum += seconds
	for i, b := range latencyBuckets {
		if seconds <= b {
			h.buckets[i]++
		}
	}
}
func (m *Metrics) Render() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var lines []string
	names := sortedKeys(m.counters)
	for _, name := range names {
		lines = append(lines, "# TYPE "+name+" counter")
		for _, key := range sortedKeys(m.counters[name]) {
			lines = append(lines, name+key+" "+strconv.FormatUint(m.counters[name][key], 10))
		}
	}
	for _, name := range sortedKeys(m.gauges) {
		lines = append(lines, "# TYPE "+name+" gauge")
		for _, key := range sortedKeys(m.gauges[name]) {
			lines = append(lines, name+key+" "+strconv.FormatFloat(m.gauges[name][key], 'f', -1, 64))
		}
	}
	for _, name := range sortedKeys(m.histograms) {
		lines = append(lines, "# TYPE "+name+" histogram")
		for _, key := range sortedKeys(m.histograms[name]) {
			h := m.histograms[name][key]
			for i, b := range latencyBuckets {
				lines = append(lines, name+"_bucket"+addLabel(key, "le", fmt.Sprintf("%g", b))+" "+strconv.FormatUint(h.buckets[i], 10))
			}
			lines = append(lines, name+"_bucket"+addLabel(key, "le", "+Inf")+" "+strconv.FormatUint(h.count, 10))
			lines = append(lines, name+"_sum"+key+" "+strconv.FormatFloat(h.sum, 'f', -1, 64))
			lines = append(lines, name+"_count"+key+" "+strconv.FormatUint(h.count, 10))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := sortedKeys(labels)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"=\""+strings.ReplaceAll(labels[k], "\"", "\\\"")+"\"")
	}
	return "{" + strings.Join(pairs, ",") + "}"
}
func addLabel(key, k, v string) string {
	if key == "" {
		return labelKey(map[string]string{k: v})
	}
	return strings.TrimSuffix(key, "}") + "," + k + "=\"" + v + "\"}"
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
