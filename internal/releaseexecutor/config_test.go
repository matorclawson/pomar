package releaseexecutor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureConfig(t *testing.T) (Config, []byte, string) {
	t.Helper()
	binding := func(id string) Binding { return Binding{id, hashBytes([]byte(id))} }
	c := Config{
		Schema: ConfigSchema, Repository: "example/engine", Branch: "main",
		TagPrefix: "engine/v", Index: "none", Platform: "darwin-arm64",
		Component: Component{"zeroemployeeorg/zeocore", strings.Repeat("a", 40), hashBytes([]byte("component")), "zeo.release-event/v1"},
		Profiles: Profiles{binding("plan"), binding("tag"), binding("build"), binding("sign"),
			binding("event"), binding("seal"), binding("publish"), binding("consumer-job")},
		Feed: binding("feed"), Consumer: binding("consumer"), Trust: binding("trust"), RuntimeAuthority: binding("runtime-authority"),
		ActivationReceipts: []string{hashBytes([]byte("synthetic-activation"))},
		ValidUntil: 2000000000, Limits: Limits{1024, 2048, 32, 32768},
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return c, b, hashBytes(b)
}

func TestConfigStrictPositiveAndRefusals(t *testing.T) {
	_, good, pin := fixtureConfig(t)
	if _, err := ParseConfig(good, pin); err != nil {
		t.Fatal(err)
	}
	// Escaped canonical names are equivalent; blanket refusal is not the guard.
	escaped := bytes.Replace(good, []byte(`"schema"`), []byte(`"\u0073chema"`), 1)
	if _, err := ParseConfig(escaped, hashBytes(escaped)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"case alias": bytes.Replace(good, []byte(`"repository"`), []byte(`"Repository"`), 1),
		"unicode alias": bytes.Replace(good, []byte(`"schema"`), []byte(`"ſchema"`), 1),
		"duplicate decoded": append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"\u0073chema":"`+ConfigSchema+`"}`)...),
		"manual version": append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"version":"99"}`)...),
		"trailing value": append(append([]byte(nil), good...), []byte(`{}`)...),
		"missing field": []byte(`{"schema":"` + ConfigSchema + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(raw, hashBytes(raw)); err == nil {
				t.Fatal("accepted malformed/unauthorised shape")
			}
		})
	}
	if _, err := ParseConfig(good, hashBytes([]byte("different"))); err == nil {
		t.Fatal("accepted changed protected bytes")
	}
}

func TestConfigRequiresEveryOwnerBinding(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Component.Commit = "main" },
		func(c *Config) { c.Component.EventSchema = "unknown" },
		func(c *Config) { c.Profiles.Sign = Binding{} },
		func(c *Config) { c.Profiles.Consumer.ID = "consumer; shell" },
		func(c *Config) { c.ActivationReceipts = []string{} },
		func(c *Config) { c.RuntimeAuthority.SHA256 = "caller-label" },
		func(c *Config) { c.Platform = "linux" },
		func(c *Config) { c.Index = "pypi" },
		func(c *Config) { c.TagPrefix = "Engine/v" },
		func(c *Config) { c.TagPrefix = "engine/extra/v" },
		func(c *Config) { c.TagPrefix = "engine_name/v" },
		func(c *Config) { c.Limits.ExpandedBytes = 0 },
	} {
		c, _, _ := fixtureConfig(t)
		change(&c)
		raw, _ := json.Marshal(c)
		if _, err := ParseConfig(raw, hashBytes(raw)); err == nil {
			t.Fatal("accepted incomplete protected binding")
		}
	}
	_, raw, _ := fixtureConfig(t)
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	v["profiles"].(map[string]any)["plan"] = nil
	b, _ := json.Marshal(v)
	if _, err := ParseConfig(b, hashBytes(b)); err == nil {
		t.Fatal("null profile accepted")
	}
}
