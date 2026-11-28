package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLinuxVenueStatusShowsUnknownSourceAndFillFloor(t *testing.T) {
	var out, errb bytes.Buffer
	if got := run([]string{"venue", "status", "-root", t.TempDir()}, &out, &errb); got != 0 {
		t.Fatalf("status = %d, stderr %q", got, errb.String())
	}
	want := "disk: unknown source, admission keeps the fill floor\n"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("output = %q; want line %q", out.String(), want)
	}
}
