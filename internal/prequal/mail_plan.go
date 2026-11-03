package prequal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MailHeader retains observed header name/value bytes and ordering. Callers
// must not canonicalize, sort, combine, or discard fields before comparison.
type MailHeader struct {
	Name  string
	Value string
}

// MailDenial is an observation, not evidence that its input ID exists. The
// owner must separately bind fixture custody and the actual original VM.
type MailDenial struct {
	Status  int
	Headers []MailHeader
	Body    []byte
}

// MailDenialComparison retains raw body digests and exact replacement counts.
// This partial GET comparison never grants full D1 acceptance or execution.
type MailDenialComparison struct {
	TemplateSHA256    string `json:"template_sha256"`
	ForeignBodySHA256 string `json:"foreign_body_sha256"`
	MissingBodySHA256 string `json:"missing_body_sha256"`
	ForeignIDCount    int    `json:"foreign_id_count"`
	MissingIDCount    int    `json:"missing_id_count"`
}

const mailIDToken = "__POMAR_VALIDATED_INPUT_ID__"
const MailDenialTemplateVersion = "pomar.pre-model-mail-denial/v1"

// MailDenialTemplate is frozen in the reviewed host plan, not supplied by a
// guest response. Its sole token marks the maintained wire's echoed ID slot.
type MailDenialTemplate struct {
	Version    string
	CallerSeat string
	Body       []byte
	SHA256     string
}

func validateMailDenialTemplate(t MailDenialTemplate) error {
	if t.Version != MailDenialTemplateVersion || !id.MatchString(t.CallerSeat) || len(t.Body) == 0 || len(t.Body) > 64<<10 {
		return errors.New("bounded pinned denial template and caller required")
	}
	h := sha256.Sum256(t.Body)
	if t.SHA256 != hex.EncodeToString(h[:]) {
		return errors.New("denial template hash mismatch")
	}
	// Architect ruling arch-pomar-m1-template-ruling-20261103 requires one
	// canonical complete response, not equality between arbitrary denials.
	want, err := json.Marshal(struct {
		Exit   int    `json:"exit"`
		Output string `json:"output"`
	}{2, fmt.Sprintf("zmail: no message %s in %s's inbox; zmsg inbox --all lists every message it has\n", mailIDToken, t.CallerSeat)})
	if err != nil || !bytes.Equal(t.Body, append(want, '\n')) || bytes.Count(t.Body, []byte(mailIDToken)) != 1 {
		return errors.New("template must match the maintained canonical denial wire")
	}
	return nil
}

// CompareMailDenials implements Council ans_8dd01de9e47f46d0 and the later
// Architect pinned-template ruling: instantiate the sole echoed input ID slot,
// compare every remaining byte, and compare all observed headers except Date
// and each body's own Content-Length. A no-echo product wire needs a newly
// reviewed template; it cannot be accepted by pairwise equality alone.
// The original bodies remain with the caller; errors never include payloads.
func CompareMailDenials(template MailDenialTemplate, foreignID, missingID string, foreign, missing MailDenial) (MailDenialComparison, error) {
	r := MailDenialComparison{}
	if err := validateMailDenialTemplate(template); err != nil {
		return r, err
	}
	r.TemplateSHA256 = template.SHA256
	if !validMailFixtureID(foreignID) || !validMailFixtureID(missingID) || foreignID == missingID {
		return r, errors.New("distinct validated fixture IDs required")
	}
	for _, d := range []MailDenial{foreign, missing} {
		if d.Status != 422 || len(d.Body) == 0 || len(d.Body) > 1<<20 || !utf8.Valid(d.Body) {
			return r, errors.New("bounded UTF-8 HTTP422 denial required")
		}
		if err := validateMailDenialBody(d.Body); err != nil {
			return r, err
		}
		if bytes.Contains(d.Body, []byte(mailIDToken)) {
			return r, errors.New("comparison token collision")
		}
	}
	for i, input := range []string{foreignID, missingID} {
		prefix, suffix, _ := bytes.Cut(template.Body, []byte(mailIDToken))
		want := append(append(bytes.Clone(prefix), []byte(input)...), suffix...)
		if !bytes.Equal([]MailDenial{foreign, missing}[i].Body, want) {
			return r, errors.New("denial differs from pinned canonical template")
		}
	}
	a, err := comparableMailHeaders(foreign)
	if err != nil {
		return r, err
	}
	b, err := comparableMailHeaders(missing)
	if err != nil {
		return r, err
	}
	if len(a) != len(b) {
		return r, errors.New("different denial headers")
	}
	for i := range a {
		if a[i] != b[i] {
			return r, errors.New("different denial headers")
		}
	}
	fh, mh := sha256.Sum256(foreign.Body), sha256.Sum256(missing.Body)
	r.ForeignBodySHA256, r.MissingBodySHA256 = hex.EncodeToString(fh[:]), hex.EncodeToString(mh[:])
	r.ForeignIDCount = bytes.Count(foreign.Body, []byte(foreignID))
	r.MissingIDCount = bytes.Count(missing.Body, []byte(missingID))
	if r.ForeignIDCount != 1 || r.MissingIDCount != 1 {
		return r, errors.New("one unambiguous echoed input ID required in each denial")
	}
	return r, nil
}

func validMailFixtureID(s string) bool {
	if len(s) == 0 || len(s) > 256 || strings.Contains(s, mailIDToken) {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validateMailDenialBody(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errors.New("denial envelope required")
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("duplicate or invalid denial field")
		}
		seen[name] = true
		switch name {
		case "exit":
			var code int
			if d.Decode(&code) != nil || code != 2 {
				return errors.New("denial must carry CLI exit2")
			}
		case "output":
			var output *string
			if d.Decode(&output) != nil || output == nil {
				return errors.New("denial output string required")
			}
		default:
			return errors.New("unknown denial field")
		}
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') || !seen["exit"] || !seen["output"] {
		return errors.New("complete denial envelope required")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("trailing denial document")
	}
	return nil
}

func comparableMailHeaders(d MailDenial) ([]MailHeader, error) {
	if len(d.Headers) > 128 {
		return nil, errors.New("bounded headers required")
	}
	var result []MailHeader
	seen := map[string]bool{}
	total := 0
	for _, h := range d.Headers {
		total += len(h.Name) + len(h.Value)
		if total > 64<<10 || h.Name == "" || strings.ContainsAny(h.Name+h.Value, "\r\n\x00") {
			return nil, errors.New("invalid or oversized denial header")
		}
		for _, c := range []byte(h.Name) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
				return nil, errors.New("invalid denial header name")
			}
		}
		name := strings.ToLower(h.Name)
		switch name {
		case "date", "content-length", "content-type":
			if seen[name] {
				return nil, errors.New("ambiguous duplicate denial header")
			}
			seen[name] = true
		}
		switch name {
		case "date":
			continue
		case "content-length":
			n, e := strconv.Atoi(h.Value)
			if e != nil || n != len(d.Body) || h.Value != strconv.Itoa(n) {
				return nil, errors.New("Content-Length disagrees with raw denial body")
			}
			continue
		case "content-type":
			if h.Value != "application/json" {
				return nil, errors.New("JSON denial Content-Type required")
			}
		}
		result = append(result, h)
	}
	if !seen["content-type"] {
		return nil, errors.New("JSON denial Content-Type required")
	}
	// Presence itself is observed: do not discard a missing length on one side.
	if seen["content-length"] {
		result = append(result, MailHeader{Name: "\x00content-length-present"})
	}
	return result, nil
}
