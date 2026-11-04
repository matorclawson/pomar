package prequal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureDenial(id string) MailDenial {
	b, _ := json.Marshal(struct {
		Exit   int    `json:"exit"`
		Output string `json:"output"`
	}{2, "zmail: no message " + id + " in pomar-d1-disposable-20261102's inbox; zmsg inbox --all lists every message it has\n"})
	b = append(b, '\n')
	return MailDenial{Status: 422, Headers: []MailHeader{{"Content-Type", "application/json"}, {"Date", "first"}, {"Content-Length", strconv.Itoa(len(b))}}, Body: b}
}

func fixtureTemplate() MailDenialTemplate {
	b := fixtureDenial(mailIDToken).Body
	h := sha256.Sum256(b)
	headers := []MailHeader{{"Content-Type", "application/json"}}
	rawHeaders, _ := json.Marshal(headers)
	hh := sha256.Sum256(rawHeaders)
	return MailDenialTemplate{Headers: headers, HeadersSHA256: hex.EncodeToString(hh[:]), Version: MailDenialTemplateVersion, CallerSeat: "pomar-d1-disposable-20261102", Body: b, SHA256: hex.EncodeToString(h[:])}
}

func fixLength(d *MailDenial) { d.Headers[2].Value = strconv.Itoa(len(d.Body)) }

func TestMailDenialsExactIDComparisonRetainsRaw(t *testing.T) {
	f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
	m.Headers[1].Value = "second"
	beforeF, beforeM := bytes.Clone(f.Body), bytes.Clone(m.Body)
	r, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m)
	if err != nil {
		t.Fatal(err)
	}
	fh, mh := sha256.Sum256(beforeF), sha256.Sum256(beforeM)
	if r.ForeignBodySHA256 != hex.EncodeToString(fh[:]) || r.MissingBodySHA256 != hex.EncodeToString(mh[:]) || r.ForeignIDCount != 1 || r.MissingIDCount != 1 {
		t.Fatalf("wrong comparison receipt: %+v", r)
	}
	if !bytes.Equal(f.Body, beforeF) || !bytes.Equal(m.Body, beforeM) {
		t.Fatal("comparison modified retained raw evidence")
	}
}

func TestMailDenialsRejectOracleAndMalformedObservations(t *testing.T) {
	tests := []struct {
		name string
		edit func(*MailDenial, *MailDenial)
	}{
		{"different output", func(f, m *MailDenial) {
			m.Body = bytes.ReplaceAll(m.Body, []byte("no message"), []byte("private message"))
			fixLength(m)
		}},
		{"whitespace difference", func(f, m *MailDenial) { m.Body = append(m.Body, ' '); fixLength(m) }},
		{"request value", func(f, m *MailDenial) {
			m.Body = bytes.ReplaceAll(m.Body, []byte("inbox"), []byte("inbox-123"))
			fixLength(m)
		}},
		{"unequal counts", func(f, m *MailDenial) {
			m.Body = bytes.ReplaceAll(m.Body, []byte("msg-missing"), []byte("msg-missing msg-missing"))
			fixLength(m)
		}},
		{"one no echo", func(f, m *MailDenial) { m.Body = []byte("{\"exit\":2,\"output\":\"denied\"}\n"); fixLength(m) }},
		{"token collision", func(f, m *MailDenial) {
			m.Body = bytes.ReplaceAll(m.Body, []byte("inbox"), []byte(mailIDToken))
			fixLength(m)
		}},
		{"status", func(f, m *MailDenial) { m.Status = 200 }},
		{"CLI exit", func(f, m *MailDenial) { m.Body = bytes.Replace(m.Body, []byte("\"exit\":2"), []byte("\"exit\":0"), 1) }},
		{"unknown JSON field", func(f, m *MailDenial) {
			m.Body = []byte("{\"exit\":2,\"output\":\"msg-missing\",\"payload\":\"secret\"}")
			fixLength(m)
		}},
		{"duplicate JSON field", func(f, m *MailDenial) {
			m.Body = []byte("{\"exit\":2,\"exit\":2,\"output\":\"msg-missing\"}")
			fixLength(m)
		}},
		{"missing JSON field", func(f, m *MailDenial) { m.Body = []byte("{\"exit\":2}"); fixLength(m) }},
		{"trailing JSON", func(f, m *MailDenial) { m.Body = append(m.Body, []byte("{}")...); fixLength(m) }},
		{"malformed JSON", func(f, m *MailDenial) { m.Body = []byte("{"); fixLength(m) }},
		{"nonstring output", func(f, m *MailDenial) { m.Body = []byte("{\"exit\":2,\"output\":null}"); fixLength(m) }},
		{"invalid UTF8", func(f, m *MailDenial) { m.Body = append(m.Body, 0xff); fixLength(m) }},
		{"empty body", func(f, m *MailDenial) { m.Body = nil; fixLength(m) }},
		{"oversize body", func(f, m *MailDenial) { m.Body = bytes.Repeat([]byte("x"), (1<<20)+1); fixLength(m) }},
		{"unapproved header", func(f, m *MailDenial) { m.Headers = append(m.Headers, MailHeader{"X-Request-ID", "one"}) }},
		{"different header value", func(f, m *MailDenial) {
			f.Headers = append(f.Headers, MailHeader{"X-Test", "one"})
			m.Headers = append(m.Headers, MailHeader{"X-Test", "two"})
		}},
		{"header case normalization", func(f, m *MailDenial) { m.Headers[0].Name = "content-type" }},
		{"wrong length", func(f, m *MailDenial) { m.Headers[2].Value = "1" }},
		{"noncanonical length", func(f, m *MailDenial) { m.Headers[2].Value = "+" + m.Headers[2].Value }},
		{"one missing length", func(f, m *MailDenial) { m.Headers = m.Headers[:2] }},
		{"duplicate length", func(f, m *MailDenial) { m.Headers = append(m.Headers, m.Headers[2]) }},
		{"duplicate date", func(f, m *MailDenial) { m.Headers = append(m.Headers, m.Headers[1]) }},
		{"no content type", func(f, m *MailDenial) { m.Headers = m.Headers[1:] }},
		{"nonJSON content type", func(f, m *MailDenial) { m.Headers[0].Value = "text/plain" }},
		{"header injection", func(f, m *MailDenial) { m.Headers = append(m.Headers, MailHeader{"X-Test", "one\r\ntwo"}) }},
		{"length marker spoof", func(f, m *MailDenial) { m.Headers = append(m.Headers[:2], MailHeader{"content-length-present", ""}) }},
		{"invalid name on both", func(f, m *MailDenial) {
			f.Headers = append(f.Headers, MailHeader{"bad name", "same"})
			m.Headers = append(m.Headers, MailHeader{"bad name", "same"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
			tt.edit(&f, &m)
			if _, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m); err == nil {
				t.Fatal("accepted invalid or distinguishable denial")
			}
		})
	}
}

func TestMailDenialsRejectPairwiseEqualNoncanonicalBodies(t *testing.T) {
	for _, raw := range []string{
		"{\"exit\":2,\"output\":\"denied\"}\n",
		"{\"exit\":2,\"output\":\"constant private payload\"}\n",
	} {
		f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
		f.Body = []byte(raw)
		m.Body = []byte(raw)
		fixLength(&f)
		fixLength(&m)
		if _, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m); err == nil {
			t.Fatal("accepted pairwise-equal noncanonical body")
		}
	}
}

func TestMailDenialsRejectUnpinnedOrDifferentCallerTemplate(t *testing.T) {
	for _, change := range []func(*MailDenialTemplate){
		func(t *MailDenialTemplate) { t.SHA256 = "" },
		func(t *MailDenialTemplate) { t.HeadersSHA256 = "" },
		func(t *MailDenialTemplate) { t.Headers[0].Value = "text/plain" },
		func(t *MailDenialTemplate) { t.Version = "unreviewed-version" },
		func(t *MailDenialTemplate) { t.CallerSeat = "another-seat" },
		func(t *MailDenialTemplate) {
			t.Body = append(t.Body, ' ')
			h := sha256.Sum256(t.Body)
			t.SHA256 = hex.EncodeToString(h[:])
		},
		func(t *MailDenialTemplate) {
			t.Body = bytes.ReplaceAll(t.Body, []byte("no message"), []byte("secret payload"))
			h := sha256.Sum256(t.Body)
			t.SHA256 = hex.EncodeToString(h[:])
		},
	} {
		template := fixtureTemplate()
		change(&template)
		if _, err := CompareMailDenials(template, "msg-foreign-existing", "msg-missing", fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")); err == nil {
			t.Fatal("accepted unpinned or mismatched template")
		}
	}
}

func TestMailDenialsValidateDistinctSafeIDs(t *testing.T) {
	for _, ids := range [][2]string{{"", "missing"}, {"same", "same"}, {"quote\"", "missing"}, {mailIDToken, "missing"}, {string(bytes.Repeat([]byte("a"), 257)), "missing"}} {
		if _, err := CompareMailDenials(fixtureTemplate(), ids[0], ids[1], fixtureDenial(ids[0]), fixtureDenial(ids[1])); err == nil {
			t.Fatal("accepted ambiguous fixture identity")
		}
	}
}

func TestMailDenialsRejectRepeatedIDAndWrongPosition(t *testing.T) {
	for _, modify := range []func([]byte, string) []byte{
		func(b []byte, id string) []byte { return bytes.Replace(b, []byte(id), []byte(id+" "+id), 1) },
		func(b []byte, id string) []byte {
			return bytes.Replace(b, []byte("no message "+id), []byte(id+" no message"), 1)
		},
	} {
		f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
		f.Body = modify(f.Body, "msg-foreign-existing")
		m.Body = modify(m.Body, "msg-missing")
		fixLength(&f)
		fixLength(&m)
		if _, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m); err == nil {
			t.Fatal("accepted IDs outside sole declared slot")
		}
	}
}

func TestMailDenialsBindPinnedHeaderSet(t *testing.T) {
	f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
	f.Headers = append(f.Headers, MailHeader{"X-Undeclared", "same"})
	m.Headers = append(m.Headers, MailHeader{"X-Undeclared", "same"})
	if _, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m); err == nil {
		t.Fatal("accepted matching but unpinned headers")
	}
}

func fixtureMailPlan(t *testing.T) (MailPlan, MailPlanBinding, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	row, receipt, evidence := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	p := MailPlan{Schema: MailPlanSchema, Operation: "original-d1", Seat: "pomar-d1-disposable-20261102", Environment: "disposable-env", Incarnation: "original-incarnation", ScopeID: "owner-scope-1", Deadline: now.Add(5 * time.Minute), RegistryRecordSHA256: row, FixtureReceiptSHA256: receipt, DenialTemplate: fixtureTemplate(), Positive: MailFixtureCase{ID: "msg-positive", Recipient: "pomar-d1-disposable-20261102", EvidenceSHA256: evidence, ExpectedOutputSHA256: strings.Repeat("4", 64)}, ForeignExisting: MailFixtureCase{ID: "msg-foreign", Recipient: "designated-test-recipient", EvidenceSHA256: evidence}, Missing: MailFixtureCase{ID: "msg-missing", Recipient: "pomar-d1-disposable-20261102", EvidenceSHA256: evidence}}
	b := MailPlanBinding{Operation: p.Operation, Seat: p.Seat, Environment: p.Environment, Incarnation: p.Incarnation, ScopeID: p.ScopeID, Deadline: p.Deadline, RegistryRecordSHA256: row, FixtureReceiptSHA256: receipt, TemplateSHA256: p.DenialTemplate.SHA256, TemplateHeadersSHA256: p.DenialTemplate.HeadersSHA256}
	return p, b, now
}

func encodeFixtureMailPlan(t *testing.T, p MailPlan, b MailPlanBinding) ([]byte, MailPlanBinding) {
	t.Helper()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	b.PlanSHA256 = hex.EncodeToString(h[:])
	return raw, b
}

func TestParseMailPlanBindsExactOriginalAndPreservesRaw(t *testing.T) {
	p, b, now := fixtureMailPlan(t)
	raw, b := encodeFixtureMailPlan(t, p, b)
	before := bytes.Clone(raw)
	got, e := ParseMailPlan(raw, b, now)
	if e != nil || got.Operation != p.Operation || got.Positive.ID != p.Positive.ID || got.ForeignExisting.Recipient != p.ForeignExisting.Recipient {
		t.Fatalf("valid fixture input: %v", e)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("parser changed exact input bytes")
	}
	other := append(bytes.Clone(raw), ' ')
	if _, e = ParseMailPlan(other, b, now); e == nil {
		t.Fatal("accepted byte substitution with the old pin")
	}
}

func TestParseMailPlanRejectsUnboundInputs(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*MailPlan)
	}{
		{"schema", func(p *MailPlan) { p.Schema = "pomar.pre-model-mail-plan/v2" }},
		{"operation", func(p *MailPlan) { p.Operation = "another-operation" }},
		{"seat", func(p *MailPlan) { p.Seat = "another-seat" }},
		{"environment", func(p *MailPlan) { p.Environment = "another-env" }},
		{"incarnation", func(p *MailPlan) { p.Incarnation = "another-incarnation" }},
		{"scope", func(p *MailPlan) { p.ScopeID = "another-owner-scope" }},
		{"deadline", func(p *MailPlan) { p.Deadline = p.Deadline.Add(time.Second) }},
		{"registry", func(p *MailPlan) { p.RegistryRecordSHA256 = strings.Repeat("9", 64) }},
		{"receipt", func(p *MailPlan) { p.FixtureReceiptSHA256 = strings.Repeat("9", 64) }},
		{"template pin", func(p *MailPlan) { p.DenialTemplate.SHA256 = strings.Repeat("9", 64) }},
		{"header pin", func(p *MailPlan) { p.DenialTemplate.HeadersSHA256 = strings.Repeat("9", 64) }},
		{"duplicate cases", func(p *MailPlan) { p.Missing.ID = p.ForeignExisting.ID }},
		{"wrong positive recipient", func(p *MailPlan) { p.Positive.Recipient = p.ForeignExisting.Recipient }},
		{"same foreign recipient", func(p *MailPlan) { p.ForeignExisting.Recipient = p.Seat }},
		{"wrong missing recipient", func(p *MailPlan) { p.Missing.Recipient = p.ForeignExisting.Recipient }},
		{"missing evidence", func(p *MailPlan) { p.ForeignExisting.EvidenceSHA256 = "" }},
		{"fixed text collision", func(p *MailPlan) { p.Missing.ID = "inbox" }},
		{"missing positive digest", func(p *MailPlan) { p.Positive.ExpectedOutputSHA256 = "" }},
		{"foreign payload digest", func(p *MailPlan) { p.ForeignExisting.ExpectedOutputSHA256 = strings.Repeat("8", 64) }},
		{"missing payload digest", func(p *MailPlan) { p.Missing.ExpectedOutputSHA256 = strings.Repeat("8", 64) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, b, now := fixtureMailPlan(t)
			tt.change(&p)
			raw, b := encodeFixtureMailPlan(t, p, b)
			got, e := ParseMailPlan(raw, b, now)
			if e == nil || got.Schema != "" {
				t.Fatal("accepted substitution or returned a partially validated plan")
			}
		})
	}
}

func TestParseMailPlanRejectsAmbiguousJSON(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"duplicate root", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema":`), []byte(`"schema":"ignored","schema":`), 1)
		}},
		{"duplicate nested", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"id":"msg-positive"`), []byte(`"id":"ignored","id":"msg-positive"`), 1)
		}},
		{"case alias", func(b []byte) []byte { return bytes.Replace(b, []byte(`"seat":`), []byte(`"Seat":`), 1) }},
		{"nested alias", func(b []byte) []byte { return bytes.Replace(b, []byte(`"Headers":`), []byte(`"headers":`), 1) }},
		{"unknown field", func(b []byte) []byte { return append([]byte(`{"extra":true,`), b[1:]...) }},
		{"missing field", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`,"expected_output_sha256":""`), nil, 1)
		}},
		{"null string", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"seat":"pomar-d1-disposable-20261102"`), []byte(`"seat":null`), 1)
		}},
		{"trailing", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"invalid UTF8", func(b []byte) []byte { return append(b, 0xff) }},
		{"oversize", func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), 64<<10)...) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, b, now := fixtureMailPlan(t)
			raw, b := encodeFixtureMailPlan(t, p, b)
			changed := tt.change(bytes.Clone(raw))
			if bytes.Equal(raw, changed) {
				t.Fatal("mutation did not reach schema fixture")
			}
			h := sha256.Sum256(changed)
			b.PlanSHA256 = hex.EncodeToString(h[:])
			if _, e := ParseMailPlan(changed, b, now); e == nil {
				t.Fatal("accepted ambiguous or malformed JSON")
			}
		})
	}
}

func TestParseMailPlanRequiresLiveBoundedOriginalDeadline(t *testing.T) {
	for _, delta := range []time.Duration{-time.Second, 0, 10*time.Minute + time.Nanosecond} {
		p, b, now := fixtureMailPlan(t)
		p.Deadline = now.Add(delta)
		b.Deadline = p.Deadline
		raw, b := encodeFixtureMailPlan(t, p, b)
		if _, e := ParseMailPlan(raw, b, now); e == nil {
			t.Fatal("accepted expired or unbounded original deadline")
		}
	}
}

func TestMailDenialsRejectIDAlsoInFixedTemplateText(t *testing.T) {
	for _, collision := range []string{"inbox", "pomar-d1-disposable-20261102"} {
		for _, foreign := range []bool{true, false} {
			fID, mID := "msg-foreign-existing", "msg-missing"
			if foreign {
				fID = collision
			} else {
				mID = collision
			}
			f, m := fixtureDenial(fID), fixtureDenial(mID)
			if bytes.Count(f.Body, []byte(fID)) == 1 && bytes.Count(m.Body, []byte(mID)) == 1 {
				t.Fatal("collision fixture did not reach repeated fixed-text ID")
			}
			if _, err := CompareMailDenials(fixtureTemplate(), fID, mID, f, m); err == nil {
				t.Fatal("accepted an ID also occurring outside the declared slot")
			}
		}
	}
}

func TestMailDenialsRejectIdenticalFixedWireDrift(t *testing.T) {
	for _, change := range []func([]byte) []byte{
		func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("pomar-d1-disposable-20261102"), []byte("different-caller"))
		},
		func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("no message"), []byte("private payload")) },
		func(b []byte) []byte { return append(b, ' ') },
	} {
		f, m := fixtureDenial("msg-foreign-existing"), fixtureDenial("msg-missing")
		f.Body, m.Body = change(f.Body), change(m.Body)
		fixLength(&f)
		fixLength(&m)
		if _, err := CompareMailDenials(fixtureTemplate(), "msg-foreign-existing", "msg-missing", f, m); err == nil {
			t.Fatal("accepted matching fixed-wire drift on both responses")
		}
	}
}
