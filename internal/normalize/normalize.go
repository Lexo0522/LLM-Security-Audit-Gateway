package normalize

import (
	"encoding/json"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

func Text(body []byte) string {
	var payload any
	if json.Unmarshal(body, &payload) == nil {
		var parts []string
		collect(payload, &parts)
		return normalize(strings.Join(parts, "\n"))
	}
	return normalize(string(body))
}

func collect(value any, parts *[]string) {
	switch item := value.(type) {
	case string:
		*parts = append(*parts, item)
	case []any:
		for _, child := range item {
			collect(child, parts)
		}
	case map[string]any:
		// Map iteration order is randomized in Go; sorting the keys keeps the
		// normalized text reproducible so rule matches are deterministic.
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collect(item[key], parts)
		}
	}
}

func normalize(value string) string {
	value = norm.NFKC.String(value)
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
