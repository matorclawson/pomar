package capacity

import (
	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"testing"
)

func TestOutputExpansionRequiresExplicitValidArtifactPolicy(t *testing.T) {
	c := CI
	c.OutputCapBytes = 128 << 20
	if c.validate() == nil {
		t.Fatal("expanded default report ceiling")
	}
	c.ArtifactOutput = &artifactreturn.Policy{PerFileBytes: 128 << 20, MaxFiles: 1, TransferSeconds: 600, Names: []string{"tree.tar"}, Provisional: true}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.ArtifactOutput.TransferSeconds = 601
	if c.validate() == nil {
		t.Fatal("unbounded artifact transfer")
	}
	c.ArtifactOutput.TransferSeconds = 600
	c.OutputCapBytes = 2 << 30
	if c.validate() == nil {
		t.Fatal("aggregate above reviewed maximum")
	}
}
