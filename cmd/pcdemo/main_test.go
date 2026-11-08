package main

import (
	"strings"
	"testing"
)

// TestDemo runs the whole dividend settlement flow and every attack. run
// returns an error if any step has an unexpected outcome.
func TestDemo(t *testing.T) {
	var out strings.Builder
	if err := run(&out); err != nil {
		t.Fatalf("%v\n\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "every attack was refused") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}
