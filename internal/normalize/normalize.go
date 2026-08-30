package normalize

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Parse returns the normalized text and the top-level "model" field from a
// JSON body in a single pass, so callers do not parse the body twice. Non-JSON
// bodies are normalized as plain text and yield an empty model.
func Parse(body []byte) (text string, model string) {
	var payload any
	if json.Unmarshal(body, &payload) == nil {
		if object, ok := payload.(map[string]any); ok {
			if value, ok := object["model"].(string); ok {
				model = value
			}
		}
		var walker walker
		walker.collect(payload)
		return normalize(strings.Join(walker.parts, "\n")), model
	}
	return normalize(string(body)), ""
}

func Text(body []byte) string {
	text, _ := Parse(body)
	return text
}

type walker struct{ parts []string }

func (w *walker) collect(value any) {
	switch item := value.(type) {
	case string:
		w.parts = append(w.parts, item)
	case []any:
		for _, child := range item {
			w.collect(child)
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
			w.collect(item[key])
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
