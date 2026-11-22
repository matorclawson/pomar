package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCoreDoesNotImportIntegrations(t *testing.T) {
	const adapters = "github.com/rodriveracom/pomar/integrations"
	const root = "../.."
	commands := filepath.Join(root, "cmd")
	integrations := filepath.Join(root, "integrations")
	checked := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Commands are composition roots. Hidden trees hold Git metadata
			// and build output.
			if path != root && (path == commands || path == integrations || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, decl := range file.Imports {
			name, err := strconv.Unquote(decl.Path.Value)
			if err != nil {
				return err
			}
			if name == adapters || strings.HasPrefix(name, adapters+"/") {
				t.Errorf("core file %s imports adapter %s", path, name)
			}
		}
		return nil
	})
	if err != nil || checked == 0 {
		t.Fatalf("could not inspect core: checked %d files: %v", checked, err)
	}
}
