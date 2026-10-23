// Package releaseexecutor defines the closed private-release adapter boundary.
// Host execution, accepted job results and signing remain owner-bound providers.
package releaseexecutor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalid = errors.New("release executor: invalid binding")
	ErrUnbound = errors.New("release executor: provider unavailable")
	ErrHeld = errors.New("release executor: original intent held")
	ErrConflict = errors.New("release executor: original identity conflict")
	ErrDurability = errors.New("release executor: durable transition unconfirmed")
)

const ConfigSchema = "pomar.private-release-config/v1"
const MaxConfigBytes = 64 << 10
const MaxEnvelopeBytes = 8 << 20

type Binding struct {
	ID string `json:"id"`
	SHA256 string `json:"sha256"`
}

type Component struct {
	Repository string `json:"repository"`
	Commit string `json:"commit"`
	SHA256 string `json:"sha256"`
	EventSchema string `json:"event_schema"`
}

type Profiles struct {
	Plan Binding `json:"plan"`
	Tag Binding `json:"tag"`
	Build Binding `json:"build"`
	Sign Binding `json:"sign"`
	Event Binding `json:"event"`
	Seal Binding `json:"seal"`
	Publish Binding `json:"publish"`
	Consumer Binding `json:"consumer"`
}

type Limits struct {
	ArtifactBytes int64 `json:"artifact_bytes"`
	ExpandedBytes int64 `json:"expanded_bytes"`
	InventoryEntries int `json:"inventory_entries"`
	EnvelopeBytes int `json:"envelope_bytes"`
}

// Config is adapter policy, not the shared component's release.yaml schema.
// Parsing it never authenticates it or establishes section 6.2 activation.
type Config struct {
	Schema string `json:"schema"`
	Repository string `json:"repository"`
	Branch string `json:"branch"`
	TagPrefix string `json:"tag_prefix"`
	Index string `json:"index"`
	Platform string `json:"platform"`
	Component Component `json:"component"`
	Profiles Profiles `json:"profiles"`
	Feed Binding `json:"feed"`
	Consumer Binding `json:"consumer"`
	Trust Binding `json:"trust"`
	RuntimeAuthority Binding `json:"runtime_authority"`
	ActivationReceipts []string `json:"activation_receipts"`
	ValidUntil int64 `json:"valid_until"`
	Limits Limits `json:"limits"`
}

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var prefixName = regexp.MustCompile(`^([a-z][a-z0-9-]*/)?v$`)
var bindingName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hexID(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validBinding(b Binding) bool {
	return bindingName.MatchString(b.ID) && hexID(b.SHA256, 64)
}

func ParseConfig(data []byte, expectedSHA256 string) (Config, error) {
	var c Config
	if !hexID(expectedSHA256, 64) || hashBytes(data) != expectedSHA256 {
		return c, ErrInvalid
	}
	if err := strictDecode(data, &c, MaxConfigBytes); err != nil {
		return Config{}, err
	}
	if err := validateConfig(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func validateConfig(c Config) error {
	if c.Schema != ConfigSchema || !repositoryName.MatchString(c.Repository) || c.Branch != "main" ||
		!prefixName.MatchString(c.TagPrefix) || c.Index != "none" || c.Platform != "darwin-arm64" ||
		c.Component.Repository != "zeroemployeeorg/zeocore" || !hexID(c.Component.Commit, 40) ||
		!hexID(c.Component.SHA256, 64) || c.Component.EventSchema != "zeo.release-event/v1" ||
		c.ValidUntil <= 0 || len(c.ActivationReceipts) == 0 || len(c.ActivationReceipts) > 64 ||
		c.Limits.ArtifactBytes <= 0 || c.Limits.ExpandedBytes <= 0 || c.Limits.InventoryEntries <= 0 || c.Limits.InventoryEntries > 32768 ||
		c.Limits.EnvelopeBytes <= 0 || c.Limits.EnvelopeBytes > MaxEnvelopeBytes {
		return ErrInvalid
	}
	bindings := []Binding{c.Profiles.Plan, c.Profiles.Tag, c.Profiles.Build, c.Profiles.Sign,
		c.Profiles.Event, c.Profiles.Seal, c.Profiles.Publish, c.Profiles.Consumer,
		c.Feed, c.Consumer, c.Trust, c.RuntimeAuthority}
	for _, b := range bindings {
		if !validBinding(b) {
			return ErrInvalid
		}
	}
	for _, h := range c.ActivationReceipts {
		if !hexID(h, 64) {
			return ErrInvalid
		}
	}
	return nil
}

// strictDecode rejects duplicate decoded keys, Go's case-fold aliases, missing
// fields, nulls and trailing values. []byte members preserve opaque shared bytes.
func strictDecode(data []byte, dst any, limit int) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return ErrInvalid
		}
		if t == json.Delim('{') {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				s, ok := key.(string)
				if err != nil || !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		} else if t == json.Delim('[') {
			for d.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil || exactShape(raw, reflect.TypeOf(dst).Elem()) != nil {
		return ErrInvalid
	}
	if json.Unmarshal(data, dst) != nil {
		return ErrInvalid
	}
	return nil
}

func exactShape(raw any, typ reflect.Type) error {
	if raw == nil {
		return ErrInvalid
	}
	switch typ.Kind() {
	case reflect.Struct:
		m, ok := raw.(map[string]any)
		if !ok || len(m) != typ.NumField() {
			return ErrInvalid
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key := f.Tag.Get("json")
			v, ok := m[key]
			if !ok || exactShape(v, f.Type) != nil {
				return ErrInvalid
			}
		}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			if _, ok := raw.(string); !ok {
				return ErrInvalid
			}
			return nil
		}
		a, ok := raw.([]any)
		if !ok {
			return ErrInvalid
		}
		for _, v := range a {
			if exactShape(v, typ.Elem()) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}
