package releaseexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// This verifier is a synthetic boundary fixture, not a new signing algorithm or
// evidence that any installed producer supports the canonical-payload contract.
type fixtureEnvelopeVerifier struct {
	claims Claims
	payload []byte
	event []byte
	badConfig bool
	badMain bool
	badContent bool
	contentCalls int
}

func (v *fixtureEnvelopeVerifier) VerifyConfig(context.Context, Config, string) error {
	if v.badConfig {
		return ErrHeld
	}
	return nil
}
func (v *fixtureEnvelopeVerifier) VerifyMain(context.Context, Observation) error {
	if v.badMain {
		return ErrHeld
	}
	return nil
}
func (v *fixtureEnvelopeVerifier) VerifyPayload(_ context.Context, b []byte, s, r, trust Binding) (Claims, error) {
	if !bytes.Equal(b, v.payload) || s.ID != "signature" || r.ID != "verification" || trust.ID != "trust" {
		return Claims{}, ErrHeld
	}
	c := v.claims
	c.Inventory = append([]Member(nil), c.Inventory...)
	return c, nil
}
func (v *fixtureEnvelopeVerifier) VerifySharedEvent(_ context.Context, b []byte, component Component, c Claims) error {
	if !bytes.Equal(b, v.event) || component.EventSchema != "zeo.release-event/v1" ||
		c.Version != "0.1.0" || c.Tag != "engine/v0.1.0" {
		return ErrHeld
	}
	return nil
}
func (v *fixtureEnvelopeVerifier) VerifyContent(_ context.Context, artifact Artifact, inventory []Member) error {
	v.contentCalls++
	if v.badContent || artifact != v.claims.Artifact || !reflect.DeepEqual(inventory, v.claims.Inventory) {
		return ErrHeld
	}
	return nil
}

func fixtureEnvelope(t *testing.T) (Envelope, Config, string, Observation, *fixtureEnvelopeVerifier) {
	t.Helper()
	c, _, pin := fixtureConfig(t)
	_, o, _, _, _ := fixtureAdapter(t)
	event := []byte("{\n  \"schema\": \"zeo.release-event/v1\"\n}\n")
	claims := Claims{
		Repository: o.Repository, Commit: o.Commit, Tree: o.Tree, Version: "0.1.0", Tag: "engine/v0.1.0", TagObject: o.Commit,
		NotesSHA256: hashBytes([]byte("notes")), ConfigSHA256: pin, ComponentSHA256: c.Component.SHA256,
		MainProofSHA256: hashBytes(o.Proof), SharedEventSHA256: hashBytes(event), BuildProfileSHA256: c.Profiles.Build.SHA256,
		ToolchainSHA256: hashBytes([]byte("tools")), LockedInputsSHA256: hashBytes([]byte("locks")), Platform: c.Platform,
		Artifact: Artifact{hashBytes([]byte("signed archive")), 100},
		Inventory: []Member{{Path: "bin", Kind: "dir", Mode: "755"},
			{Path: "bin/dt", Kind: "file", Mode: "755", Bytes: 3, SHA256: hashBytes([]byte("run"))}},
		ValidUntil: 1990000000,
	}
	payload := []byte(`{"fixture":"owner-canonical-payload"}`)
	e := Envelope{EnvelopeSchema, claims, event, payload, hashBytes(payload),
		Binding{"signature", hashBytes([]byte("signature"))}, Binding{"verification", hashBytes([]byte("verification"))}}
	trusted := claims
	trusted.Inventory = append([]Member(nil), claims.Inventory...)
	v := &fixtureEnvelopeVerifier{claims: trusted, payload: append([]byte(nil), payload...), event: append([]byte(nil), event...)}
	return e, c, pin, o, v
}

func verifyFixture(t *testing.T, e Envelope, c Config, pin string, o Observation, v EnvelopeVerifier) error {
	t.Helper()
	b, err := EncodeEnvelope(e)
	if err != nil {
		return err
	}
	_, err = VerifyEnvelope(context.Background(), b, c, pin, o, time.Unix(1900000000, 0), v)
	return err
}

func TestEnvelopeAuthenticatesFinalRelocatedContentAndPreservesSharedBytes(t *testing.T) {
	e, c, pin, o, v := fixtureEnvelope(t)
	if err := verifyFixture(t, e, c, pin, o, v); err != nil || v.contentCalls != 1 {
		t.Fatal("legitimate bound fixture refused", err)
	}
	b, _ := EncodeEnvelope(e)
	r, err := VerifyEnvelope(context.Background(), b, c, pin, o, time.Unix(1900000000, 0), v)
	if err != nil || !bytes.Equal(r.SharedEvent, e.SharedEvent) || !bytes.Equal(r.CanonicalPayload, e.CanonicalPayload) {
		t.Fatal("changed original event/payload bytes", err)
	}
}

func TestRehashedPayloadIsNotAnAuthenticSignature(t *testing.T) {
	e, c, pin, o, v := fixtureEnvelope(t)
	e.CanonicalPayload = []byte(`{"fixture":"attacker-rehashed"}`)
	e.PayloadSHA256 = hashBytes(e.CanonicalPayload)
	if err := verifyFixture(t, e, c, pin, o, v); err == nil || v.contentCalls != 0 {
		t.Fatal("trusted recomputed hash as authenticity", err)
	}
}

func TestEnvelopeRefusesWrongBindingsAndIncompleteContent(t *testing.T) {
	for _, change := range []func(*Envelope, *fixtureEnvelopeVerifier){
		func(e *Envelope, v *fixtureEnvelopeVerifier) { e.Claims.Tree = e.Claims.Commit },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { e.Claims.Inventory[1].SHA256 = hashBytes([]byte("changed")) },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { e.SignatureReceipt.ID = "substituted" },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { v.badMain = true },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { v.badConfig = true },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { v.badContent = true },
		func(e *Envelope, v *fixtureEnvelopeVerifier) { e.Claims.ValidUntil = 1; v.claims.ValidUntil = 1 },
		func(e *Envelope, v *fixtureEnvelopeVerifier) {
			e.SharedEvent = []byte(`{"schema":"unknown"}`)
			e.Claims.SharedEventSHA256 = hashBytes(e.SharedEvent)
			v.claims.SharedEventSHA256 = e.Claims.SharedEventSHA256
		},
	} {
		e, c, pin, o, v := fixtureEnvelope(t)
		change(&e, v)
		if err := verifyFixture(t, e, c, pin, o, v); err == nil {
			t.Fatal("accepted invalid authenticated/content binding")
		}
	}
	e, c, pin, o, _ := fixtureEnvelope(t)
	if err := verifyFixture(t, e, c, pin, o, nil); !errors.Is(err, ErrUnbound) {
		t.Fatal("missing verifier did not hold", err)
	}
}

func TestInventoryRefusesAliasesEscapesMissingParentsAndSizeOverflow(t *testing.T) {
	file := func(p string) Member { return Member{Path: p, Kind: "file", Mode: "644", Bytes: 1, SHA256: hashBytes([]byte("x"))} }
	for _, items := range [][]Member{
		{file("../outside")}, {file("/absolute")}, {file("bad\\path")},
		{file("K"), file("K")}, {file("bin/dt")},
		{file("bin"), file("bin/dt")},
		{{Path: "link", Kind: "symlink", Mode: "-", Target: "../outside"}},
	} {
		if err := validateInventory(items, 32, 2048); err == nil {
			t.Fatal("unsafe/incomplete inventory accepted", items)
		}
	}
	x := file("large")
	x.Bytes = 1<<63 - 1
	if validateInventory([]Member{x, file("other")}, 32, 2048) == nil {
		t.Fatal("expanded-byte overflow accepted")
	}
	if validateInventory([]Member{file("ok")}, 32, 2048) != nil {
		t.Fatal("blanket inventory refusal")
	}
}

func TestOuterEnvelopeUnknownAndDuplicateFieldsRefuse(t *testing.T) {
	e, c, pin, o, v := fixtureEnvelope(t)
	b, _ := json.Marshal(e)
	for _, suffix := range []string{`,"schema":"` + EnvelopeSchema + `"}`, `,"Schema":"` + EnvelopeSchema + `"}`} {
		x := append(append([]byte(nil), b[:len(b)-1]...), []byte(suffix)...)
		if _, err := VerifyEnvelope(context.Background(), x, c, pin, o, time.Unix(1900000000, 0), v); err == nil {
			t.Fatal("duplicate/alias envelope accepted")
		}
	}
}
