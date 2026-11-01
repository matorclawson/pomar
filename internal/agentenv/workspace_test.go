package agentenv

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSourceWorkingDirectorySharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/seat-work-destinations.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name        string  `json:"name"`
		Destination string  `json:"destination"`
		Valid       bool    `json:"valid"`
		CWD         *string `json:"cwd"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			got, err := SourceWorkingDirectory(v.Destination)
			if (err == nil) != v.Valid {
				t.Fatalf("valid=%v got%q err%v", v.Valid, got, err)
			}
			if v.Valid && (v.CWD == nil || got != *v.CWD) {
				t.Fatalf("cwd%q expected%v", got, v.CWD)
			}
			if !v.Valid && got != "" {
				t.Fatal("refused path returned usable cwd")
			}
		})
	}
}
