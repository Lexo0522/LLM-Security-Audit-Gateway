package stream

import (
	"bufio"
	"bytes"
	"context"
	"io"
)

type Scanner struct {
	tail   []byte
	window int
}

func NewScanner(window int) *Scanner {
	if window <= 0 {
		window = 256
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

func Copy(ctx context.Context, dst io.Writer, src io.Reader, inspect func([]byte) bool) error {
	reader := bufio.NewReaderSize(src, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if !inspect(line) {
				return io.ErrClosedPipe
			}
			if _, writeErr := dst.Write(line); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func EventText(data []byte) []byte { return bytes.TrimSpace(bytes.TrimPrefix(data, []byte("data:"))) }
