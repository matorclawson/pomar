package manager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type artifactTransport func(*http.Request) (*http.Response, error)

func (f artifactTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func artifactClientFixture(t *testing.T) ([]byte, ed25519.PublicKey, artifactreturn.Expected) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	pub := private.Public().(ed25519.PublicKey)
	class := artifactClassForTest()
	want := artifactreturn.Expected{Attempt: "art-1", Class: class.Name, Mirror: "app", Ref: "main", SourceGit: true, SourceSHA: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64), CommandSHA256: strings.Repeat("c", 64), PackageSet: strings.Repeat("d", 64), RootfsSHA256: strings.Repeat("e", 64), KeyID: sha(string(pub)), CallerUID: 503, PolicySHA256: artifactreturn.PolicyDigest(*class.ArtifactOutput, class.OutputCapBytes)}
	result := map[string]any{"schema": "pomar.result/v1", "attempt": want.Attempt, "class": class, "mirror": want.Mirror, "ref": want.Ref, "git": true, "sha": want.SourceSHA, "image_digest": want.ImageDigest, "command_sha256": want.CommandSHA256, "package_set": want.PackageSet, "rootfs_sha256": want.RootfsSHA256, "host": want.KeyID, "started_by_uid": want.CallerUID, "state": "exited", "exit_code": 0, "artifact_output_count": 2, "outputs": []OutputRecord{{Name: "one", Status: OutputOK, Bytes: 3, SHA256: sha("abc")}, {Name: "two", Status: OutputOK, Bytes: 3, SHA256: sha("xyz")}}}
	raw, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := json.Marshal(ResultReply{Result: raw, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)), KeyID: want.KeyID})
	if e != nil {
		t.Fatal(e)
	}
	return envelope, pub, want
}
func artifactReply(r *http.Request, status int, data []byte, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data)), Header: headers, Request: r}
}
func artifactReceiveRoot(t *testing.T) *os.Root {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestArtifactClientVerifiesOriginalThenFetchesClosedSet(t *testing.T) {
	reply, key, want := artifactClientFixture(t)
	parent := artifactReceiveRoot(t)
	calls := 0
	c := &Client{http: &http.Client{Transport: artifactTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("unbounded request")
		}
		if !r.Close {
			t.Fatal("reusable artifact response connection")
		}
		if r.URL.Path == "/v1/attempts/art-1/result" {
			return artifactReply(r, 200, reply, http.Header{}), nil
		}
		if _, e := parent.Stat(".partial-art-1/ORIGINAL-RESULT.json"); e != nil {
			t.Fatal("payload requested before original claim", e)
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/attempts/art-1/outputs/")
		payload := map[string]string{"one": "abc", "two": "xyz"}[name]
		if payload == "" {
			t.Fatal("unexpected output request", r.URL.Path)
		}
		header := http.Header{}
		header.Set(OutputSHA256Header, sha(payload))
		return artifactReply(r, 200, []byte(payload), header), nil
	})}}
	accepted, e := c.ReceiveArtifacts(context.Background(), parent, "art-1", key, want)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 3 || accepted != ".partial-art-1" {
		t.Fatal("incomplete request/acceptance", calls, accepted)
	}
	for name, wanted := range map[string]string{"one": "abc", "two": "xyz"} {
		data, e := parent.ReadFile(accepted + "/" + name)
		if e != nil || string(data) != wanted {
			t.Fatal("wrong artifact", name, e)
		}
	}
	before := calls
	if _, e := c.ReceiveArtifacts(context.Background(), parent, "art-1", key, want); e == nil {
		t.Fatal("replayed original receive")
	}
	if calls != before+1 {
		t.Fatal("replayed payload fetch")
	}
}
func TestArtifactClientRejectsUntrustedResultBeforePayload(t *testing.T) {
	for _, kind := range []string{"signature", "redirect", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			reply, key, want := artifactClientFixture(t)
			parent := artifactReceiveRoot(t)
			calls := 0
			c := &Client{http: &http.Client{Transport: artifactTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					t.Fatal("payload or redirect followed")
				}
				switch kind {
				case "signature":
					reply = bytes.Replace(reply, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
				case "redirect":
					h := http.Header{}
					h.Set("Location", "http://elsewhere/target")
					return artifactReply(r, 302, nil, h), nil
				case "oversize":
					reply = bytes.Repeat([]byte(" "), artifactreturn.MaxResultBytes+1)
				}
				return artifactReply(r, 200, reply, http.Header{}), nil
			})}}
			if path, e := c.ReceiveArtifacts(context.Background(), parent, "art-1", key, want); e == nil || path != "" {
				t.Fatal("untrusted result accepted")
			}
			if calls != 1 {
				t.Fatalf("wrong refusal boundary, requests=%d", calls)
			}
			if _, e := parent.Stat(".partial-art-1"); !os.IsNotExist(e) {
				t.Fatal("untrusted result created a claim")
			}
		})
	}
}
func TestArtifactClientRejectsDifferentHeadersAndTamperedBytes(t *testing.T) {
	for _, kind := range []string{"length", "hash", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			reply, key, want := artifactClientFixture(t)
			parent := artifactReceiveRoot(t)
			calls := 0
			c := &Client{http: &http.Client{Transport: artifactTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.HasSuffix(r.URL.Path, "/result") {
					return artifactReply(r, 200, reply, http.Header{}), nil
				}
				payload := []byte("abc")
				h := http.Header{}
				h.Set(OutputSHA256Header, sha("abc"))
				if kind == "hash" {
					h.Set(OutputSHA256Header, sha("bad"))
				}
				if kind == "bytes" {
					payload = []byte("bad")
				}
				response := artifactReply(r, 200, payload, h)
				if kind == "length" {
					response.ContentLength = 4
				}
				return response, nil
			})}}
			if path, e := c.ReceiveArtifacts(context.Background(), parent, "art-1", key, want); e == nil || path != "" {
				t.Fatal("tampered artifact accepted")
			}
			if calls != 2 {
				t.Fatalf("wrong refusal boundary, requests=%d", calls)
			}
		})
	}
}

func TestArtifactClientRefusesPublicDestinationBeforeRequest(t *testing.T) {
	reply, key, want := artifactClientFixture(t)
	_ = reply
	parent := artifactReceiveRoot(t)
	if err := os.Chmod(parent.Name(), 0755); err != nil {
		t.Fatal(err)
	}
	c := &Client{http: &http.Client{Transport: artifactTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP before private destination")
		return nil, nil
	})}}
	if _, err := c.ReceiveArtifacts(context.Background(), parent, "art-1", key, want); err == nil {
		t.Fatal("public destination accepted")
	}
}
