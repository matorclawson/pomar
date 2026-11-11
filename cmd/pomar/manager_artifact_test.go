package main

import (
	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"os"
	"strings"
	"testing"
)

func TestArtifactClassRefusesNonRootOptInFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary contributing user")
	}
	p := profileFixture()
	p[1].ArtifactOutput = &artifactreturn.Policy{PerFileBytes: 128 << 20, MaxFiles: 1, TransferSeconds: 60, Names: []string{"tree.tar"}, Provisional: true}
	p[1].OutputCapBytes = 128 << 20
	_, _, err := readClassProfiles(writeProfiles(t, p), fixtureUID)
	if err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatal("unprotected artifact opt-in accepted", err)
	}
}
