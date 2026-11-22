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
	// Commands are composition roots. Core packages belong to internal or
	// notification and must also keep their test dependencies adapter-free.
	for _, root := range []string{"..", "../../notification"} {
		checked := 0
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
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
			t.Fatalf("could not inspect core root %s: checked %d files: %v", root, checked, err)
		}
	}
}
