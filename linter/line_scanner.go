package linter

import (
	"bufio"
	"io"
	"strings"
)

const (
	stdoutLineBufferSize = 64 << 10
	maxStdoutLineSize    = 16 << 20
)

type lineScanner struct {
	reader    *bufio.Reader
	maxSize   int
	text      string
	err       error
	oversized bool
}

func newLineScanner(reader io.Reader, maxSize int) *lineScanner {
	return &lineScanner{
		reader:  bufio.NewReaderSize(reader, stdoutLineBufferSize),
		maxSize: maxSize,
	}
}

func (s *lineScanner) Scan() bool {
	s.text = ""
	s.oversized = false
	if s.err != nil {
		return false
	}

	var line []byte
	for {
		fragment, err := s.reader.ReadSlice('\n')
		lineSize := len(line) + len(fragment)
		if err == nil && len(fragment) > 0 && fragment[len(fragment)-1] == '\n' {
			lineSize--
		}
		if !s.oversized {
			if lineSize > s.maxSize {
				s.oversized = true
				line = nil
			} else {
				line = append(line, fragment...)
			}
		}

		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			s.err = err
			if !s.oversized && len(line) > 0 {
				s.text = strings.TrimSuffix(string(line), "\n")
				s.text = strings.TrimSuffix(s.text, "\r")
				return true
			}
			return s.oversized
		}

		if !s.oversized {
			s.text = strings.TrimSuffix(string(line), "\n")
			s.text = strings.TrimSuffix(s.text, "\r")
		}
		return true
	}
}

func (s *lineScanner) Text() string {
	return s.text
}

func (s *lineScanner) Err() error {
	return s.err
}

func (s *lineScanner) Oversized() bool {
	return s.oversized
}
