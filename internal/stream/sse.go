package stream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	DefaultAuditWindowBytes = 16 << 10
	DefaultMaxEventBytes    = 256 << 10
)

var (
	ErrInspectionBlocked = errors.New("SSE event blocked by inspection")
	ErrEventTooLarge     = errors.New("SSE event exceeds configured limit")
)

// Event preserves the upstream event exactly while exposing normalized data and
// OpenAI-compatible content fragments for inspection.
type Event struct {
	Raw       []byte
	Data      []byte
	Done      bool
	Fragments []Fragment
}

// Fragment is an independently-windowed semantic channel. It prevents an
// unrelated choice or tool call from being concatenated with another one.
type Fragment struct {
	Channel string
	Text    []byte
}

type Inspector func(Event) bool

// Copy forwards complete SSE events exactly as received. The inspector runs
// before each event is written, so a rejected event is never exposed.
func Copy(ctx context.Context, dst io.Writer, src io.Reader, maxEventBytes int, inspect Inspector) error {
	if maxEventBytes <= 0 {
		maxEventBytes = DefaultMaxEventBytes
	}
	reader := bufio.NewReaderSize(src, 32*1024)
	for {
		event, err := readEvent(reader, maxEventBytes)
		if event != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if inspect != nil && !inspect(*event) {
				return ErrInspectionBlocked
			}
			if _, writeErr := dst.Write(event.Raw); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func readEvent(reader *bufio.Reader, maxEventBytes int) (*Event, error) {
	var raw bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 {
			// ReadSlice avoids allocating an arbitrarily large line before its
			// contribution to the complete event can be checked against the cap.
			if raw.Len()+len(line) > maxEventBytes {
				return nil, ErrEventTooLarge
			}
			raw.Write(line)
			if err == nil && isBlankLine(line) {
				return parseEvent(raw.Bytes()), nil
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if raw.Len() == 0 {
					return nil, io.EOF
				}
				return parseEvent(raw.Bytes()), io.EOF
			}
			return nil, err
		}
	}
}

func isBlankLine(line []byte) bool {
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	return len(line) == 0
}

func parseEvent(raw []byte) *Event {
	dataLines := make([][]byte, 0)
	for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !bytes.HasPrefix(line, []byte("data")) {
			continue
		}
		if len(line) == len("data") {
			dataLines = append(dataLines, nil)
			continue
		}
		if line[len("data")] != ':' {
			continue
		}
		value := line[len("data:"):]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
		dataLines = append(dataLines, value)
	}
	data := bytes.Join(dataLines, []byte("\n"))
	event := &Event{Raw: append([]byte(nil), raw...), Data: data, Done: bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]"))}
	if !event.Done {
		event.Fragments = ExtractFragments(data)
	}
	return event
}

// ExtractFragments extracts only documented OpenAI streaming content fields.
// Unknown JSON is intentionally ignored so the proxy stays wire-compatible.
func ExtractFragments(data []byte) []Fragment {
	var responseEvent struct {
		Type         string `json:"type"`
		ItemID       string `json:"item_id"`
		OutputIndex  *int   `json:"output_index"`
		ContentIndex *int   `json:"content_index"`
		SummaryIndex *int   `json:"summary_index"`
		Delta        string `json:"delta"`
	}
	if err := json.Unmarshal(data, &responseEvent); err != nil {
		return nil
	}
	if responseEvent.Type != "" {
		return responseFragments(responseEvent.Type, responseEvent.ItemID, responseEvent.OutputIndex, responseEvent.ContentIndex, responseEvent.SummaryIndex, responseEvent.Delta)
	}

	var payload struct {
		Choices []struct {
			Index *int   `json:"index"`
			Text  string `json:"text"`
			Delta struct {
				Content      string `json:"content"`
				FunctionCall struct {
					Arguments string `json:"arguments"`
				} `json:"function_call"`
				ToolCalls []struct {
					Index    *int `json:"index"`
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	fragments := make([]Fragment, 0)
	for choicePosition, choice := range payload.Choices {
		choiceIndex := choicePosition
		if choice.Index != nil {
			choiceIndex = *choice.Index
		} else {
			choiceIndex = choicePosition
		}
		if choice.Delta.Content != "" {
			fragments = append(fragments, Fragment{Channel: "chat:choice:" + strconv.Itoa(choiceIndex) + ":content", Text: []byte(choice.Delta.Content)})
		}
		if choice.Delta.FunctionCall.Arguments != "" {
			fragments = append(fragments, Fragment{Channel: "chat:choice:" + strconv.Itoa(choiceIndex) + ":function_call:arguments", Text: []byte(choice.Delta.FunctionCall.Arguments)})
		}
		for toolPosition, toolCall := range choice.Delta.ToolCalls {
			toolIndex := toolPosition
			if toolCall.Index != nil {
				toolIndex = *toolCall.Index
			} else {
				toolIndex = toolPosition
			}
			if toolCall.Function.Arguments != "" {
				fragments = append(fragments, Fragment{Channel: "chat:choice:" + strconv.Itoa(choiceIndex) + ":tool:" + strconv.Itoa(toolIndex) + ":arguments", Text: []byte(toolCall.Function.Arguments)})
			}
		}
		if choice.Text != "" {
			fragments = append(fragments, Fragment{Channel: "completion:choice:" + strconv.Itoa(choiceIndex) + ":text", Text: []byte(choice.Text)})
		}
	}
	return fragments
}

// responseFragments extracts the text-bearing incremental events documented by
// the Responses API (https://platform.openai.com/docs/api-reference/responses-streaming).
// The channel includes both the event kind and its semantic item/index identity,
// preventing unrelated response outputs from sharing a rolling inspection window.
func responseFragments(eventType, itemID string, outputIndex, contentIndex, summaryIndex *int, delta string) []Fragment {
	if delta == "" {
		return nil
	}
	var channel string
	switch eventType {
	case "response.output_text.delta", "response.refusal.delta", "response.reasoning_text.delta":
		channel = responseChannel(eventType, itemID, outputIndex, "content", contentIndex)
	case "response.reasoning_summary_text.delta":
		channel = responseChannel(eventType, itemID, outputIndex, "summary", summaryIndex)
	case "response.function_call_arguments.delta":
		channel = responseChannel(eventType, itemID, outputIndex, "", nil)
	default:
		return nil
	}
	return []Fragment{{Channel: channel, Text: []byte(delta)}}
}

func responseChannel(eventType, itemID string, outputIndex *int, suffix string, suffixIndex *int) string {
	item := itemID
	if item == "" {
		item = "unknown"
	}
	channel := "responses:" + eventType + ":item:" + item + ":output:" + responseIndex(outputIndex)
	if suffix != "" {
		channel += ":" + suffix + ":" + responseIndex(suffixIndex)
	}
	return channel
}

func responseIndex(index *int) string {
	if index == nil {
		return "unknown"
	}
	return strconv.Itoa(*index)
}

type Windows struct {
	window int
	byKey  map[string]*Scanner
}

func NewWindows(window int) *Windows {
	if window <= 0 {
		window = DefaultAuditWindowBytes
	}
	return &Windows{window: window, byKey: map[string]*Scanner{}}
}

func (w *Windows) Feed(channel string, chunk []byte) []byte {
	scanner := w.byKey[channel]
	if scanner == nil {
		scanner = NewScanner(w.window)
		w.byKey[channel] = scanner
	}
	return scanner.Feed(chunk)
}

type Scanner struct {
	tail   []byte
	window int
}

func NewScanner(window int) *Scanner {
	if window <= 0 {
		window = DefaultAuditWindowBytes
	}
	return &Scanner{window: window}
}

func (s *Scanner) Feed(chunk []byte) []byte {
	data := append(append([]byte{}, s.tail...), chunk...)
	if len(data) > s.window {
		s.tail = append([]byte{}, data[len(data)-s.window:]...)
	} else {
		s.tail = append([]byte{}, data...)
	}
	return data
}

func SecurityTermination(code, requestID string) []byte {
	message := "stream response blocked by audit policy"
	if code == "sse_event_too_large" {
		message = "stream event exceeds configured size limit"
	}
	return []byte(fmt.Sprintf("event: gateway.security_terminated\ndata: {\"error\":{\"type\":\"security_termination\",\"code\":%s,\"message\":%s,\"request_id\":%s}}\n\n", jsonString(code), jsonString(message), jsonString(requestID)))
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func Flush(writer io.Writer) {
	if flusher, ok := writer.(interface{ Flush() error }); ok {
		_ = flusher.Flush()
		return
	}
	if flusher, ok := writer.(interface{ Flush() }); ok {
		flusher.Flush()
	}
}

func EventText(data []byte) []byte { return bytes.TrimSpace(bytes.TrimPrefix(data, []byte("data:"))) }
