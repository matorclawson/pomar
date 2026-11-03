package prequal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
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

// MailDenialComparison retains raw body digests and exact input-ID counts.
// This partial GET comparison never grants full D1 acceptance or execution.
type MailDenialComparison struct {
	TemplateSHA256        string `json:"template_sha256"`
	TemplateHeadersSHA256 string `json:"template_headers_sha256"`
	ForeignBodySHA256     string `json:"foreign_body_sha256"`
	MissingBodySHA256     string `json:"missing_body_sha256"`
	ForeignIDCount        int    `json:"foreign_id_count"`
	MissingIDCount        int    `json:"missing_id_count"`
}

const mailIDToken = "__POMAR_VALIDATED_INPUT_ID__"
const MailDenialTemplateVersion = "pomar.pre-model-mail-denial/v1"
const MailPlanSchema = "pomar.pre-model-mail-plan/v3"

type MailFixtureCase struct {
	ID                   string `json:"id"`
	Recipient            string `json:"recipient"`
	EvidenceSHA256       string `json:"evidence_sha256"`
	ExpectedOutputSHA256 string `json:"expected_output_sha256"`
}

// MailPlan contains no fixture body or host credentials. Receipt/provenance and
// actual VM mapping must still be verified by the owning adapter, independently.
type MailPlan struct {
	Schema               string             `json:"schema"`
	Operation            string             `json:"operation"`
	Seat                 string             `json:"seat"`
	Environment          string             `json:"environment"`
	Incarnation          string             `json:"incarnation"`
	ScopeID              string             `json:"scope_id"`
	Deadline             time.Time          `json:"original_deadline"`
	RegistryRecordSHA256 string             `json:"registry_record_sha256"`
	FixtureReceiptSHA256 string             `json:"fixture_receipt_sha256"`
	DenialTemplate       MailDenialTemplate `json:"denial_template"`
	Positive             MailFixtureCase    `json:"positive"`
	ForeignExisting      MailFixtureCase    `json:"foreign_existing"`
	Missing              MailFixtureCase    `json:"missing"`
}

// MailPlanBinding must come from the independently admitted host Plan and the
// actual original VM handle, never by copying fields from the guest document.
type MailPlanBinding struct {
	Operation, Seat, Environment, Incarnation, ScopeID     string
	Deadline                                               time.Time
	PlanSHA256, RegistryRecordSHA256, FixtureReceiptSHA256 string
	TemplateSHA256, TemplateHeadersSHA256                  string
}

// ParseMailPlan verifies exact bounded bytes and pure input bindings only. It
// neither acquires a host file nor attests custodian authority or execution.
func ParseMailPlan(raw []byte, binding MailPlanBinding, now time.Time) (MailPlan, error) {
	var p MailPlan
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return p, errors.New("bounded UTF-8 mail plan required")
	}
	h := sha256.Sum256(raw)
	if !sha.MatchString(binding.PlanSHA256) || binding.PlanSHA256 != hex.EncodeToString(h[:]) {
		return p, errors.New("mail plan byte hash mismatch")
	}
	if err := strictMailJSON(raw, &p); err != nil {
		return MailPlan{}, err
	}
	if p.Schema != MailPlanSchema || !id.MatchString(binding.Operation) || !id.MatchString(binding.Seat) || !id.MatchString(binding.Environment) || !id.MatchString(binding.Incarnation) || binding.ScopeID == "" || len(binding.ScopeID) > 256 || strings.ContainsAny(binding.ScopeID, "\r\n\x00") {
		return MailPlan{}, errors.New("valid original mail plan binding required")
	}
	if p.Operation != binding.Operation || p.Seat != binding.Seat || p.Environment != binding.Environment || p.Incarnation != binding.Incarnation || p.ScopeID != binding.ScopeID || !p.Deadline.Equal(binding.Deadline) || !p.Deadline.After(now) || p.Deadline.Sub(now) > 10*time.Minute {
		return MailPlan{}, errors.New("mail plan differs from live original identities or deadline")
	}
	if !sha.MatchString(binding.RegistryRecordSHA256) || !sha.MatchString(binding.FixtureReceiptSHA256) || p.RegistryRecordSHA256 != binding.RegistryRecordSHA256 || p.FixtureReceiptSHA256 != binding.FixtureReceiptSHA256 {
		return MailPlan{}, errors.New("mail plan receipt or original row pin mismatch")
	}
	if p.DenialTemplate.CallerSeat != binding.Seat || p.DenialTemplate.SHA256 != binding.TemplateSHA256 || p.DenialTemplate.HeadersSHA256 != binding.TemplateHeadersSHA256 {
		return MailPlan{}, errors.New("mail template differs from admitted host pins")
	}
	if err := validateMailDenialTemplate(p.DenialTemplate); err != nil {
		return MailPlan{}, err
	}
	if !validMailFixtureID(p.Positive.ID) || !validMailFixtureID(p.ForeignExisting.ID) || !validMailFixtureID(p.Missing.ID) || p.Positive.ID == p.ForeignExisting.ID || p.Positive.ID == p.Missing.ID || p.ForeignExisting.ID == p.Missing.ID {
		return MailPlan{}, errors.New("three distinct valid mail fixture IDs required")
	}
	if p.Positive.Recipient != binding.Seat || !id.MatchString(p.ForeignExisting.Recipient) || p.ForeignExisting.Recipient == binding.Seat || p.Missing.Recipient != binding.Seat {
		return MailPlan{}, errors.New("exact positive, foreign and missing recipient bindings required")
	}
	for _, c := range []MailFixtureCase{p.Positive, p.ForeignExisting, p.Missing} {
		if !sha.MatchString(c.EvidenceSHA256) || bytes.Count(p.DenialTemplate.Body, []byte(c.ID)) != 0 {
			return MailPlan{}, errors.New("fixture evidence pin or unambiguous input ID required")
		}
	}
	if !sha.MatchString(p.Positive.ExpectedOutputSHA256) || p.ForeignExisting.ExpectedOutputSHA256 != "" || p.Missing.ExpectedOutputSHA256 != "" {
		return MailPlan{}, errors.New("only positive fixture may carry output digest")
	}
	return p, nil
}

// strictMailJSON rejects exact and case-aliased unknown/duplicate fields at
// every typed object boundary before ordinary decoding can overwrite a value.
func strictMailJSON(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := scanMailJSON(d, reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing mail plan document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return errors.New("invalid typed mail plan")
	}
	return nil
}

func scanMailJSON(d *json.Decoder, typ reflect.Type) error {
	if typ == reflect.TypeFor[time.Time]() {
		t, e := d.Token()
		if _, ok := t.(string); e != nil || !ok {
			return errors.New("mail deadline string required")
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		t, e := d.Token()
		if e != nil || t != json.Delim('{') {
			return errors.New("mail plan object required")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			t, e = d.Token()
			name, ok := t.(string)
			field, exists := fields[name]
			if e != nil || !ok || !exists || seen[name] {
				return errors.New("unknown or duplicate mail plan field")
			}
			seen[name] = true
			if e = scanMailJSON(d, field); e != nil {
				return e
			}
		}
		if t, e = d.Token(); e != nil || t != json.Delim('}') {
			return errors.New("incomplete mail plan object")
		}
		if len(seen) != len(fields) {
			return errors.New("mail plan fields must be explicit")
		}
		return nil
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			t, e := d.Token()
			if _, ok := t.(string); e != nil || !ok {
				return errors.New("base64 mail template bytes required")
			}
			return nil
		}
		t, e := d.Token()
		if e != nil || t != json.Delim('[') {
			return errors.New("mail header array required")
		}
		for d.More() {
			if e = scanMailJSON(d, typ.Elem()); e != nil {
				return e
			}
		}
		if t, e = d.Token(); e != nil || t != json.Delim(']') {
			return errors.New("incomplete mail header array")
		}
		return nil
	default:
		t, e := d.Token()
		if e != nil || t == nil {
			return errors.New("explicit non-null mail plan value required")
		}
		if typ.Kind() == reflect.String {
			if _, ok := t.(string); !ok {
				return errors.New("mail plan string required")
			}
		}
		return nil
	}
}

// MailDenialTemplate is frozen in the reviewed host plan, not supplied by a
// guest response. Its sole token marks the maintained wire's echoed ID slot.
type MailDenialTemplate struct {
	Version       string
	CallerSeat    string
	Body          []byte
	SHA256        string
	Headers       []MailHeader
	HeadersSHA256 string
}

func validateMailDenialTemplate(t MailDenialTemplate) error {
	if t.Version != MailDenialTemplateVersion || !id.MatchString(t.CallerSeat) || len(t.Body) == 0 || len(t.Body) > 64<<10 {
		return errors.New("bounded pinned denial template and caller required")
	}
	h := sha256.Sum256(t.Body)
	if t.SHA256 != hex.EncodeToString(h[:]) {
		return errors.New("denial template hash mismatch")
	}
	// The pinned header set excludes only the two explicit dynamic fields.
	// Its JSON-array bytes (MailHeader Name/Value fields, no trailing newline)
	// form a separate exact SHA256 input recorded in the host plan.
	if len(t.Headers) == 0 || len(t.Headers) > 128 {
		return errors.New("bounded pinned template header set required")
	}
	for _, header := range t.Headers {
		if strings.EqualFold(header.Name, "Date") || strings.EqualFold(header.Name, "Content-Length") {
			return errors.New("dynamic headers cannot be pinned as template fields")
		}
	}
	if _, err := comparableMailHeaders(MailDenial{Headers: t.Headers, Body: t.Body}); err != nil {
		return err
	}
	headerBytes, err := json.Marshal(t.Headers)
	if err != nil {
		return errors.New("invalid template headers")
	}
	hh := sha256.Sum256(headerBytes)
	if t.HeadersSHA256 != hex.EncodeToString(hh[:]) {
		return errors.New("template header set hash mismatch")
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
	r.TemplateHeadersSHA256 = template.HeadersSHA256
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
	actual := a
	if len(actual) > 0 && actual[len(actual)-1].Name == "\x00content-length-present" {
		actual = actual[:len(actual)-1]
	}
	if len(actual) != len(template.Headers) {
		return r, errors.New("denial headers differ from pinned template set")
	}
	for i := range actual {
		if actual[i] != template.Headers[i] {
			return r, errors.New("denial headers differ from pinned template set")
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
