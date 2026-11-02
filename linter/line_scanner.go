package linter

import (
	"bufio"
	"io"
	"strings"
)

const (
	stdoutLineBufferSize = 64 << 10
	maxStdoutLineSize    = 16 << 20
	maxStderrLineSize    = 64 << 10
)

// lineScanner reads newline-terminated lines up to maxSize bytes.  Unlike
// bufio.Scanner, a longer line does not stop the scanner: it is consumed
// through its newline, reported via Oversized, and only its first maxSize
// bytes are retained, so subsequent lines are still read in sync.
type lineScanner struct {
	reader    *bufio.Reader
	maxSize   int
	line      []byte
	size      int
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
	s.line = nil
	s.size = 0
	s.oversized = false
	if s.err != nil {
		return false
	}

	for {
		fragment, err := s.reader.ReadSlice('\n')
		if err == nil {
			fragment = fragment[:len(fragment)-1]
		}
		s.size += len(fragment)
		if keep := s.maxSize - len(s.line); keep > 0 {
			s.line = append(s.line, fragment[:min(keep, len(fragment))]...)
		}
		s.oversized = s.size > s.maxSize

		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			s.err = err
			return s.size > 0
		}
		return true
	}
}

// Text returns the current line, truncated to maxSize bytes if Oversized.
func (s *lineScanner) Text() string {
	if s.oversized {
		return string(s.line)
	}
	return strings.TrimSuffix(string(s.line), "\r")
}

// Size returns the full length of the current line, including any discarded bytes.
func (s *lineScanner) Size() int {
	return s.size
}

func (s *lineScanner) Err() error {
	return s.err
}

func (s *lineScanner) Oversized() bool {
	return s.oversized
}
