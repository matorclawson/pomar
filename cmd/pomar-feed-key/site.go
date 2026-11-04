package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Site values belong to the private owner deployment, outside the public
// mechanism. This closed root-owned file is fixed, never a CLI or env override.
const siteBindingPath = "/Library/Application Support/pomar-feed-policy/custody.json"

type siteBinding struct {
	Schema     string `json:"schema"`
	Hostname   string `json:"hostname"`
	PublicBase string `json:"public_base"`
}

func parseSiteBinding(raw []byte) (siteBinding, error) {
	var s siteBinding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || s.Schema != "pomar.feed-site-binding/v1" || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(s.Hostname) {
		return siteBinding{}, fmt.Errorf("closed site binding invalid")
	}
	if !filepath.IsAbs(s.PublicBase) || filepath.Clean(s.PublicBase) != s.PublicBase || s.PublicBase == "/" || s.PublicBase == custodyHome || strings.HasPrefix(s.PublicBase, custodyHome+string(filepath.Separator)) {
		return siteBinding{}, fmt.Errorf("public namespace binding invalid")
	}
	return s, nil
}
func loadSiteBinding() (siteBinding, error) {
	raw, e := protectedPolicy(siteBindingPath)
	if e != nil {
		return siteBinding{}, e
	}
	return parseSiteBinding(raw)
}
