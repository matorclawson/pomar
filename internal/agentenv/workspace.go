package agentenv

import (
	"errors"
	"strings"
)

const WorkspaceMountRoot = "/work"

// SourceWorkingDirectory validates spelling only; filesystem custody and
// retained-disk validation are separate requirements. Empty is the explicit
// legacy root. Never clean or normalize a declaration's path or digest.
func SourceWorkingDirectory(destination string) (string, error) {
	if destination == "" {
		return WorkspaceMountRoot, nil
	}
	if len(destination) > 1024 {
		return "", errors.New("source destination exceeds path bound")
	}
	for _, b := range []byte(destination) {
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-' || b == '/') {
			return "", errors.New("source destination must use ASCII path components")
		}
	}
	for _, c := range strings.Split(destination, "/") {
		if len(c) == 0 || len(c) > 255 || c == "." || c == ".." {
			return "", errors.New("source destination must have bounded nonempty relative components")
		}
	}
	return WorkspaceMountRoot + "/" + destination, nil
}
