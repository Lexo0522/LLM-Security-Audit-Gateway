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
// Writes are sharded so the request hot path never queues on a single lock;
// Render briefly snapshots each shard and merges them.
type Metrics struct{ shards [metricShards]metricShard }

const metricShards = 32

type metricShard struct {
	mu         sync.Mutex
	counters   map[string]map[string]uint64
	gauges     map[string]map[string]float64
	histograms map[string]map[string]*histogram
}

type histogram struct {
	count   uint64
	sum     float64
	buckets []uint64
}

var latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2, 5}

func NewMetrics() *Metrics {
	m := &Metrics{}
	for i := range m.shards {
		m.shards[i] = metricShard{counters: map[string]map[string]uint64{}, gauges: map[string]map[string]float64{}, histograms: map[string]map[string]*histogram{}}
	}
	return m
}

// metricShardIndex is an allocation-free FNV-1a over name and label key.
func metricShardIndex(name, key string) int {
	h := uint32(2166136261)
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	h ^= 0
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h % metricShards)
}

func (m *Metrics) Set(name string, value float64, labels map[string]string) {
	if m == nil {
		return
	}
	key := labelKey(labels)
	shard := &m.shards[metricShardIndex(name, key)]
	shard.mu.Lock()
	if shard.gauges[name] == nil {
		shard.gauges[name] = map[string]float64{}
	}
	shard.gauges[name][key] = value
	shard.mu.Unlock()
}
func (m *Metrics) Inc(name string, labels map[string]string) {
	m.Add(name, 1, labels)
}

func (m *Metrics) Add(name string, value uint64, labels map[string]string) {
	if m == nil || value == 0 {
		return
	}
	key := labelKey(labels)
	shard := &m.shards[metricShardIndex(name, key)]
	shard.mu.Lock()
	if shard.counters[name] == nil {
		shard.counters[name] = map[string]uint64{}
	}
	shard.counters[name][key] += value
	shard.mu.Unlock()
}
func (m *Metrics) Observe(name string, seconds float64, labels map[string]string) {
	if m == nil {
		return
	}
	key := labelKey(labels)
	shard := &m.shards[metricShardIndex(name, key)]
	shard.mu.Lock()
	if shard.histograms[name] == nil {
		shard.histograms[name] = map[string]*histogram{}
	}
	h := shard.histograms[name][key]
	if h == nil {
		h = &histogram{buckets: make([]uint64, len(latencyBuckets))}
		shard.histograms[name][key] = h
	}
	h.count++
	h.sum += seconds
	for i, b := range latencyBuckets {
		if seconds <= b {
			h.buckets[i]++
		}
	}
	shard.mu.Unlock()
}
func (m *Metrics) Render() string {
	if m == nil {
		return ""
	}
	counters := map[string]map[string]uint64{}
	gauges := map[string]map[string]float64{}
	histograms := map[string]map[string]*histogram{}
	for i := range m.shards {
		shard := &m.shards[i]
		shard.mu.Lock()
		for name, keys := range shard.counters {
			if counters[name] == nil {
				counters[name] = map[string]uint64{}
			}
			for key, value := range keys {
				counters[name][key] += value
			}
		}
		for name, keys := range shard.gauges {
			if gauges[name] == nil {
				gauges[name] = map[string]float64{}
			}
			for key, value := range keys {
				gauges[name][key] = value
			}
		}
		for name, keys := range shard.histograms {
			if histograms[name] == nil {
				histograms[name] = map[string]*histogram{}
			}
			for key, h := range keys {
				merged := histograms[name][key]
				if merged == nil {
					merged = &histogram{buckets: make([]uint64, len(latencyBuckets))}
					histograms[name][key] = merged
				}
				merged.count += h.count
				merged.sum += h.sum
				for i, b := range h.buckets {
					merged.buckets[i] += b
				}
			}
		}
		shard.mu.Unlock()
	}
	var lines []string
	names := sortedKeys(counters)
	for _, name := range names {
		lines = append(lines, "# TYPE "+name+" counter")
		for _, key := range sortedKeys(counters[name]) {
			lines = append(lines, name+key+" "+strconv.FormatUint(counters[name][key], 10))
		}
	}
	for _, name := range sortedKeys(gauges) {
		lines = append(lines, "# TYPE "+name+" gauge")
		for _, key := range sortedKeys(gauges[name]) {
			lines = append(lines, name+key+" "+strconv.FormatFloat(gauges[name][key], 'f', -1, 64))
		}
	}
	for _, name := range sortedKeys(histograms) {
		lines = append(lines, "# TYPE "+name+" histogram")
		for _, key := range sortedKeys(histograms[name]) {
			h := histograms[name][key]
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
