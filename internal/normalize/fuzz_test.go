package normalize

import (
	"strings"
	"testing"
)

// FuzzParse guards the audit hot path: any input must produce lowercase
// normalized text without panicking, and non-JSON input must round-trip
// through the plain-text branch.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{"stream":true,"nested":{"b":1,"a":"x"}}`))
	f.Add([]byte(`{"a":"\u200bzero\u200fwidth"}`))
	f.Add([]byte("plain text body\r\nwith lines"))
	f.Add([]byte(`{"truncated":`))
	f.Fuzz(func(t *testing.T, body []byte) {
		text, model, stream := Parse(body)
		if text != strings.ToLower(text) {
			t.Fatalf("normalized text is not lowercase: %q", text)
		}
		if strings.ContainsFunc(text, func(r rune) bool { return r == 0x200b || r == 0x200f }) {
			t.Fatalf("format characters survived normalization: %q", text)
		}
		if len(body) == 0 || body[0] != '{' {
			if model != "" || stream {
				t.Fatalf("non-JSON body must not yield metadata: model=%q stream=%v", model, stream)
			}
		}
	})
}
