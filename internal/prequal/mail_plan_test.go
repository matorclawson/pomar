package prequal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
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
