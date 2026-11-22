package serviceupgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureManifest() Manifest {
	f := FilePin{strings.Repeat("a", 64), 123}
	b := Build{Pin: strings.Repeat("b", 40), HostPin: strings.Repeat("c", 40), Binaries: map[string]FilePin{"pomar": f, "pomar-host": f}}
	m := Manifest{Schema: "pomar.service-upgrade/v1", Host: "mac-example", OperatorUID: 501, OwnerUID: 410, CallerUID: 65020, Baseline: b, Target: b, InstallRecord: f, KeyID: strings.Repeat("d", 64), CertificateSHA1: strings.Repeat("e", 40), Entitlements: f, Retained: map[string]FilePin{}}
	m.Target.Pin = strings.Repeat("f", 40)
	m.SigningPolicy = "internal_certificate"
	for _, n := range retained {
		m.Retained[n] = f
	}
	return m
}
func TestManifestRejectsAmbiguousOrUnboundPayloads(t *testing.T) {
	m := fixtureManifest()
	raw, _ := json.Marshal(m)
	if _, e := Decode(raw, digest(raw)); e != nil {
		t.Fatal(e)
	}
	for name, edit := range map[string]func([]byte) []byte{
		"wrong anchor": func(b []byte) []byte { return append(b, ' ') },
		"duplicate field": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"host":`, `"host":"other","host":`, 1))
		},
		"unknown field":   func(b []byte) []byte { return append([]byte(`{"command":"/bin/sh",`), b[1:]...) },
		"trailing object": func(b []byte) []byte { return append(b, []byte(`{}`)...) },
	} {
		t.Run(name, func(t *testing.T) {
			b := edit(raw)
			sha := digest(b)
			if name == "wrong anchor" {
				sha = digest(raw)
			}
			if _, e := Decode(b, sha); e == nil {
				t.Fatal("accepted ambiguous manifest")
			}
		})
	}
	m.Target.Binaries["/etc/sudoers"] = m.InstallRecord
	raw, _ = json.Marshal(m)
	if _, e := Decode(raw, digest(raw)); e == nil {
		t.Fatal("accepted arbitrary path")
	}
}

func TestIdentifierProfiles(t *testing.T) {
	m := fixtureManifest()
	if m.serviceLabel(false) != legacyLabel || m.serviceLabel(true) != legacyLabel {
		t.Fatal("v1 no longer selects the legacy layout")
	}
	targetPlist := FilePin{strings.Repeat("1", 64), 321}
	m.Identifiers = &Identifiers{Mode: "legacy_to_neutral", TargetPlist: &targetPlist}
	if err := m.Validate(); err == nil {
		t.Fatal("v1 accepted migration")
	}
	m.Schema = "pomar.service-upgrade/v2"
	if err := m.Validate(); err == nil {
		t.Fatal("migration accepted equal binary bindings")
	}
	target := FilePin{strings.Repeat("2", 64), 123}
	m.Target.Binaries = map[string]FilePin{"pomar": target, "pomar-host": target}
	raw, _ := json.Marshal(m)
	m, err := Decode(raw, digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	if m.serviceLabel(false) != legacyLabel || m.serviceLabel(true) != neutralLabel ||
		m.signingID("pomar", false) != "ac.zeo.pomar.pomar" ||
		m.signingID("pomar-host", true) != "io.github.rodriveracom.pomar.pomar-host" {
		t.Fatal("manifest did not bind the exact identities for each side")
	}
	m.Identifiers.TargetPlist = nil
	if err := m.Validate(); err == nil {
		t.Fatal("migration accepted an unbound target plist")
	}
	m.Identifiers.Mode = "neutral"
	if err := m.Validate(); err != nil || m.serviceLabel(false) != neutralLabel || m.serviceLabel(true) != neutralLabel {
		t.Fatalf("neutral upgrade invalid: %v", err)
	}
	m.Identifiers.TargetPlist = &targetPlist
	if err := m.Validate(); err == nil {
		t.Fatal("neutral upgrades cannot replace the retained plist")
	}
	m.Identifiers.Mode = "legacy_to_neutral"
	m.Identifiers.LegacyDevelopmentIdentifiers = map[string]string{"pomar": "pomar", "pomar-host": "pomar-host"}
	if err := m.Validate(); err == nil {
		t.Fatal("certificate-backed migrations cannot override the legacy identifiers")
	}
	m.SigningPolicy = "development_transition"
	m.CertificateSHA1 = ""
	if err := m.Validate(); err != nil || m.signingID("pomar", false) != "pomar" || m.signingID("pomar", true) != neutralPrefix+"pomar" {
		t.Fatalf("pinned legacy development identifier invalid: %v", err)
	}
	m.Identifiers.LegacyDevelopmentIdentifiers["pomar"] = `x" or identifier "y`
	if err := m.Validate(); err == nil {
		t.Fatal("accepted an identifier that can modify the signing requirement")
	}
}
