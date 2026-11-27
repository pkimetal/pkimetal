package server

import (
	"testing"

	"github.com/pkimetal/pkimetal/linter"
)

func TestLinterQueueExceedsThreshold(t *testing.T) {
	queueAtThreshold := &linter.Linter{ReqChannel: make(chan linter.LintingRequest, 8)}
	for range 6 {
		queueAtThreshold.ReqChannel <- linter.LintingRequest{}
	}

	emptyQueue := &linter.Linter{ReqChannel: make(chan linter.LintingRequest, 8)}
	queueAboveThreshold := &linter.Linter{ReqChannel: make(chan linter.LintingRequest, 8)}
	for range 7 {
		queueAboveThreshold.ReqChannel <- linter.LintingRequest{}
	}

	tests := []struct {
		name          string
		linters       linter.LinterSlice
		thresholdPerc int
		want          bool
	}{
		{name: "empty queues", linters: linter.LinterSlice{emptyQueue}, thresholdPerc: 75, want: false},
		{name: "exactly at threshold", linters: linter.LinterSlice{queueAtThreshold}, thresholdPerc: 75, want: false},
		{name: "above threshold", linters: linter.LinterSlice{queueAboveThreshold}, thresholdPerc: 75, want: true},
		{name: "one queue above threshold", linters: linter.LinterSlice{queueAtThreshold, queueAboveThreshold}, thresholdPerc: 75, want: true},
		{name: "unbuffered queue", linters: linter.LinterSlice{{ReqChannel: make(chan linter.LintingRequest)}}, thresholdPerc: 75, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linterQueueExceedsThreshold(tt.linters, tt.thresholdPerc); got != tt.want {
				t.Errorf("linterQueueExceedsThreshold() = %t, want %t", got, tt.want)
			}
		})
	}
}
