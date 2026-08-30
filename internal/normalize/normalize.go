package normalize

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

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
	value = stripFormatChars(value)
	value = norm.NFKC.String(value)
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

// stripFormatChars removes Unicode Cf (format) characters such as zero-width
// spaces and direction marks. NFKC preserves them, so without this step
// inserting a zero-width character would split any keyword and evade matching.
func stripFormatChars(value string) string {
	isFormat := func(r rune) bool { return unicode.In(r, unicode.Cf) }
	if !strings.ContainsFunc(value, isFormat) {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		if !isFormat(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
