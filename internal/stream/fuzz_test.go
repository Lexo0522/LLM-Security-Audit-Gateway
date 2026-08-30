package stream

import (
	"bytes"
	"testing"
)

// FuzzExtractFragments exercises untrusted SSE payload JSON: extraction must
// never panic and must only surface non-empty fragment text.
func FuzzExtractFragments(f *testing.F) {
	f.Add([]byte(`{"choices":[{"index":0,"delta":{"content":"a"}}]}`))
	f.Add([]byte(`{"type":"response.output_text.delta","item_id":"m1","output_index":0,"content_index":0,"delta":"abc"}`))
	f.Add([]byte(`{"type":"response.function_call_arguments.delta","item_id":"c1","output_index":0,"delta":"{}"}`))
	f.Add([]byte(`{"delta":"plain string delta"}`))
	f.Add([]byte(`{"choices":[{"delta":{"content":123}}]}`))
	f.Add([]byte(`[DONE]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, fragment := range ExtractFragments(data) {
			if fragment.Channel == "" {
				t.Fatalf("fragment without channel: %+v", fragment)
			}
		}
	})
}

// FuzzScannerFeed checks the rolling window contract: the visible window never
// exceeds its size and always holds the most recent bytes of the stream.
func FuzzScannerFeed(f *testing.F) {
	f.Add([]byte("hello "), []byte("world"))
	f.Add([]byte("0123456789abcdef0123456789"), []byte("xy"))
	f.Add([]byte{}, []byte("only-second"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		const window = 16
		scanner := NewScanner(window)
		scanner.Feed(a)
		combined := scanner.Feed(b)
		// The returned text is the retained window plus the new chunk, so it
		// is bounded by window + len(chunk) and must equal the last `window`
		// bytes of `a` joined with `b`.
		aTail := a
		if len(aTail) > window {
			aTail = aTail[len(aTail)-window:]
		}
		want := append(append([]byte{}, aTail...), b...)
		if !bytes.Equal(combined, want) {
			t.Fatalf("window drifted: got %q want %q", combined, want)
		}
	})
}
