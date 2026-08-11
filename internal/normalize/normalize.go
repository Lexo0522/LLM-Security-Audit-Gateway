package normalize

import (
	"encoding/json"
	"golang.org/x/text/unicode/norm"
	"strings"
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
		for _, child := range item {
			collect(child, parts)
		}
	}
}

func normalize(value string) string {
	value = norm.NFKC.String(value)
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
