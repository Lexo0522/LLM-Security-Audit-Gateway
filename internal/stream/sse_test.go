package stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type splitReader struct {
	data []byte
	step int
}

func (r *splitReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.step
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestCopyPreservesRawEventsAcrossArbitraryChunks(t *testing.T) {
	raw := ": comment\r\nid: event-1\r\nevent: update\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\r\ndata: \r\n\r\ndata: [DONE]\n\n"
	var copied bytes.Buffer
	var events []Event
	err := Copy(context.Background(), &copied, &splitReader{data: []byte(raw), step: 1}, DefaultMaxEventBytes, func(event Event) bool {
		events = append(events, event)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if copied.String() != raw {
		t.Fatalf("raw SSE changed:\n got %q\nwant %q", copied.String(), raw)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d", len(events))
	}
	if got, want := string(events[0].Data), "{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n"; got != want {
		t.Fatalf("data=%q want %q", got, want)
	}
	if got := fragmentsByChannel(events[0].Fragments); !sameFragments(got, map[string]string{"chat:choice:0:content": "hel"}) {
		t.Fatalf("multiline data was not extracted: %#v", events[0].Fragments)
	}
	if !events[1].Done || len(events[1].Fragments) != 0 {
		t.Fatalf("DONE event was audited: %#v", events[1])
	}
}

func TestCopyKeepsCommentsEmptyDataAndNonJSONCompatible(t *testing.T) {
	raw := ": keepalive\n\ndata:\n\ndata: plain text\n\n"
	var copied bytes.Buffer
	var events []Event
	err := Copy(context.Background(), &copied, strings.NewReader(raw), DefaultMaxEventBytes, func(event Event) bool {
		events = append(events, event)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if copied.String() != raw || len(events) != 3 {
		t.Fatalf("copied=%q events=%d", copied.String(), len(events))
	}
	if string(events[1].Data) != "" || len(events[1].Fragments) != 0 || string(events[2].Data) != "plain text" || len(events[2].Fragments) != 0 {
		t.Fatalf("unexpected compatibility parsing: %#v", events)
	}
}

func TestCopyRejectsOversizedEventBeforeForwarding(t *testing.T) {
	input := "data: " + strings.Repeat("a", 80) + "\n\n"
	var copied bytes.Buffer
	called := false
	err := Copy(context.Background(), &copied, &splitReader{data: []byte(input), step: 3}, 64, func(Event) bool {
		called = true
		return true
	})
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("error=%v", err)
	}
	if called || copied.Len() != 0 {
		t.Fatalf("oversized event was inspected or forwarded: called=%v copied=%q", called, copied.Bytes())
	}
}

func TestExtractFragmentsAndWindowsKeepChannelsIndependent(t *testing.T) {
	chat := ExtractFragments([]byte(`{"choices":[{"index":2,"delta":{"content":"answer","function_call":{"arguments":"{\"old\":true}"},"tool_calls":[{"index":4,"function":{"arguments":"{\"tool\":true}"}}]}}]}`))
	if got, want := fragmentsByChannel(chat), map[string]string{
		"chat:choice:2:content":                 "answer",
		"chat:choice:2:function_call:arguments": `{"old":true}`,
		"chat:choice:2:tool:4:arguments":        `{"tool":true}`,
	}; !sameFragments(got, want) {
		t.Fatalf("chat fragments=%#v", got)
	}
	completion := ExtractFragments([]byte(`{"choices":[{"index":1,"text":"legacy"}]}`))
	if got, want := fragmentsByChannel(completion), map[string]string{"completion:choice:1:text": "legacy"}; !sameFragments(got, want) {
		t.Fatalf("completion fragments=%#v", got)
	}
	firstTool := ExtractFragments([]byte(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":3,"function":{"arguments":"{\"na"}}]}}]}`))
	secondTool := ExtractFragments([]byte(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":3,"function":{"arguments":"me\":\"value\"}"}}]}}]}`))
	if got, want := fragmentsByChannel(firstTool), map[string]string{"chat:choice:0:tool:3:arguments": `{"na`}; !sameFragments(got, want) {
		t.Fatalf("first tool fragment=%#v", got)
	}
	if got, want := fragmentsByChannel(secondTool), map[string]string{"chat:choice:0:tool:3:arguments": `me":"value"}`}; !sameFragments(got, want) {
		t.Fatalf("second tool fragment=%#v", got)
	}
	if fragments := ExtractFragments([]byte(`{"choices":[{"delta":{"role":"assistant"}}]}`)); len(fragments) != 0 {
		t.Fatalf("unknown stream structure was audited: %#v", fragments)
	}

	windows := NewWindows(8)
	if got := string(windows.Feed("chat:choice:0:content", []byte("need"))); got != "need" {
		t.Fatalf("first window=%q", got)
	}
	if got := string(windows.Feed("chat:choice:0:tool:0:arguments", []byte("le"))); got != "le" {
		t.Fatalf("independent tool window=%q", got)
	}
	if got := string(windows.Feed("chat:choice:0:content", []byte("le"))); got != "needle" {
		t.Fatalf("cross-event content window=%q", got)
	}
	if got := string(windows.Feed("chat:choice:0:content", []byte("-123456789"))); got != "needle-123456789" {
		t.Fatalf("window/current content=%q", got)
	}
	toolWindow := NewWindows(32)
	for _, fragment := range firstTool {
		toolWindow.Feed(fragment.Channel, fragment.Text)
	}
	for _, fragment := range secondTool {
		if got := string(toolWindow.Feed(fragment.Channel, fragment.Text)); got != `{"name":"value"}` {
			t.Fatalf("cross-event tool window=%q", got)
		}
	}
}

func TestExtractResponsesFragmentsAndWindowsKeepChannelsIndependent(t *testing.T) {
	tests := []struct {
		name string
		data string
		want map[string]string
	}{
		{
			name: "output text",
			data: `{"type":"response.output_text.delta","item_id":"msg-1","output_index":2,"content_index":3,"delta":"answer"}`,
			want: map[string]string{"responses:response.output_text.delta:item:msg-1:output:2:content:3": "answer"},
		},
		{
			name: "function arguments",
			data: `{"type":"response.function_call_arguments.delta","item_id":"fc-1","output_index":4,"delta":"{\"name\":true}"}`,
			want: map[string]string{"responses:response.function_call_arguments.delta:item:fc-1:output:4": `{"name":true}`},
		},
		{
			name: "refusal",
			data: `{"type":"response.refusal.delta","item_id":"msg-2","output_index":5,"content_index":6,"delta":"cannot"}`,
			want: map[string]string{"responses:response.refusal.delta:item:msg-2:output:5:content:6": "cannot"},
		},
		{
			name: "reasoning text",
			data: `{"type":"response.reasoning_text.delta","item_id":"reason-1","output_index":7,"content_index":8,"delta":"think"}`,
			want: map[string]string{"responses:response.reasoning_text.delta:item:reason-1:output:7:content:8": "think"},
		},
		{
			name: "reasoning summary",
			data: `{"type":"response.reasoning_summary_text.delta","item_id":"reason-2","output_index":9,"summary_index":10,"delta":"summary"}`,
			want: map[string]string{"responses:response.reasoning_summary_text.delta:item:reason-2:output:9:summary:10": "summary"},
		},
		{
			name: "missing optional identifiers",
			data: `{"type":"response.output_text.delta","delta":"fallback"}`,
			want: map[string]string{"responses:response.output_text.delta:item:unknown:output:unknown:content:unknown": "fallback"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := fragmentsByChannel(ExtractFragments([]byte(test.data))); !sameFragments(got, test.want) {
				t.Fatalf("fragments=%#v want=%#v", got, test.want)
			}
		})
	}
	for _, data := range []string{
		`{"type":"response.created","response":{"id":"resp-1"}}`,
		`{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"delta":0}`,
		`{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"delta":""}`,
	} {
		if fragments := ExtractFragments([]byte(data)); len(fragments) != 0 {
			t.Fatalf("unsupported Responses event was audited: %#v", fragments)
		}
	}

	windows := NewWindows(32)
	textFirst := ExtractFragments([]byte(`{"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"nee"}`))[0]
	textSecond := ExtractFragments([]byte(`{"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"dle"}`))[0]
	otherContent := ExtractFragments([]byte(`{"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":1,"delta":"separate"}`))[0]
	function := ExtractFragments([]byte(`{"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"tool"}`))[0]
	summary := ExtractFragments([]byte(`{"type":"response.reasoning_summary_text.delta","item_id":"reason-1","output_index":0,"summary_index":0,"delta":"summary"}`))[0]
	if got := string(windows.Feed(textFirst.Channel, textFirst.Text)); got != "nee" {
		t.Fatalf("first response text window=%q", got)
	}
	if got := string(windows.Feed(otherContent.Channel, otherContent.Text)); got != "separate" {
		t.Fatalf("other content window=%q", got)
	}
	if got := string(windows.Feed(function.Channel, function.Text)); got != "tool" {
		t.Fatalf("function window=%q", got)
	}
	if got := string(windows.Feed(summary.Channel, summary.Text)); got != "summary" {
		t.Fatalf("summary window=%q", got)
	}
	if got := string(windows.Feed(textSecond.Channel, textSecond.Text)); got != "needle" {
		t.Fatalf("cross-event Responses text window=%q", got)
	}
}

func TestSecurityTerminationDoesNotExposeInspectionDetails(t *testing.T) {
	got := string(SecurityTermination("stream_policy_blocked", "request-1"))
	want := "event: gateway.security_terminated\ndata: {\"error\":{\"type\":\"security_termination\",\"code\":\"stream_policy_blocked\",\"message\":\"stream response blocked by audit policy\",\"request_id\":\"request-1\"}}\n\n"
	if got != want {
		t.Fatalf("termination=%q", got)
	}
	if strings.Contains(got, "rule") || strings.Contains(got, "evidence") || strings.Contains(got, "risk") {
		t.Fatalf("termination leaked inspection detail: %s", got)
	}
}

func fragmentsByChannel(fragments []Fragment) map[string]string {
	result := make(map[string]string, len(fragments))
	for _, fragment := range fragments {
		result[fragment.Channel] = string(fragment.Text)
	}
	return result
}

func sameFragments(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			return false
		}
	}
	return true
}
