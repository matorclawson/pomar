package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zeroemployeeorg/pomar/internal/artifactreturn"
	"github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/manager"
)

func cliArtifactHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func cliArtifactBinding(t *testing.T) (artifactBinding, ed25519.PublicKey, ed25519.PrivateKey, capacity.Class) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	public := private.Public().(ed25519.PublicKey)
	class := capacity.CI
	class.OutputCapBytes = 8
	class.ArtifactOutput = &artifactreturn.Policy{PerFileBytes: 8, MaxFiles: 1, TransferSeconds: 10, Names: []string{"tree.tar"}, Provisional: true}
	binding := artifactBinding{Schema: artifactBindingSchema, Attempt: "cli-art-1", Class: class.Name, Mirror: "app", Ref: "main", SourceSHA: strings.Repeat("a", 40), SourceGit: true, ImageDigest: "sha256:" + strings.Repeat("b", 64), PackageSet: strings.Repeat("c", 64), RootfsSHA256: strings.Repeat("d", 64), CommandSHA256: strings.Repeat("e", 64), PolicySHA256: artifactreturn.PolicyDigest(*class.ArtifactOutput, 8), KeyID: cliArtifactHash(public), CallerUID: 503}
	return binding, public, private, class
}
func TestArtifactBindingRequiresClosedExplicitUnambiguousTuple(t *testing.T) {
	binding, _, _, _ := cliArtifactBinding(t)
	raw, _ := json.Marshal(binding)
	if _, err := decodeArtifactBinding(raw); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{"duplicate": bytes.Replace(raw, []byte(`"attempt":`), []byte(`"attempt":"other","attempt":`), 1), "case-alias": bytes.Replace(raw, []byte(`"attempt":`), []byte(`"Attempt":`), 1), "missing": bytes.Replace(raw, []byte(`"readonly_source":false,`), nil, 1), "null-mode": bytes.Replace(raw, []byte(`"readonly_source":false`), []byte(`"readonly_source":null`), 1), "trailing": append(append([]byte(nil), raw...), []byte(" {}")...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeArtifactBinding(bad); err == nil {
				t.Fatal("ambiguous binding accepted")
			}
		})
	}
}
func TestArtifactSetCLIReceivesVerifiedWholeSetAndNeverReplaysPayload(t *testing.T) {
	binding, public, private, class := cliArtifactBinding(t)
	payload := []byte("tar")
	document := map[string]any{"schema": "pomar.result/v1", "attempt": binding.Attempt, "class": class, "mirror": binding.Mirror, "ref": binding.Ref, "git": true, "sha": binding.SourceSHA, "image_digest": binding.ImageDigest, "package_set": binding.PackageSet, "rootfs_sha256": binding.RootfsSHA256, "command_sha256": binding.CommandSHA256, "host": binding.KeyID, "started_by_uid": binding.CallerUID, "state": "exited", "exit_code": 0, "artifact_output_count": 1, "outputs": []manager.OutputRecord{{Name: "tree.tar", Status: manager.OutputOK, Bytes: int64(len(payload)), SHA256: cliArtifactHash(payload)}}}
	raw, _ := json.Marshal(document)
	reply, _ := json.Marshal(manager.ResultReply{Result: raw, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)), KeyID: binding.KeyID})
	temp, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(temp)
	socket := filepath.Join(temp, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var results, outputs atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutating artifact client request")
			w.WriteHeader(405)
			return
		}
		switch r.URL.Path {
		case "/v1/attempts/cli-art-1/result":
			results.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write(reply)
		case "/v1/attempts/cli-art-1/outputs/tree.tar":
			outputs.Add(1)
			w.Header().Set("Content-Length", "3")
			w.Header().Set(manager.OutputSHA256Header, cliArtifactHash(payload))
			w.Write(payload)
		default:
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	parent := filepath.Join(temp, "received")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(temp, "binding.json")
	bindingRaw, _ := json.Marshal(binding)
	if err := os.WriteFile(file, bindingRaw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"attempt", "artifact-set", "-socket", socket, "-id", binding.Attempt, "-binding", file, "-public-key", base64.StdEncoding.EncodeToString(public), "-out-dir", parent}
	var out, stderr bytes.Buffer
	if exit := run(args, &out, &stderr); exit != 0 {
		t.Fatalf("receive exit%d: %s", exit, stderr.String())
	}
	var receipt map[string]string
	if err := json.Unmarshal(out.Bytes(), &receipt); err != nil || receipt["state"] != "complete" {
		t.Fatal("invalid complete receipt", err, out.String())
	}
	data, err := os.ReadFile(filepath.Join(receipt["path"], "tree.tar"))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatal("accepted wrong file", err)
	}
	out.Reset()
	stderr.Reset()
	if exit := run(args, &out, &stderr); exit != 1 || out.Len() != 0 {
		t.Fatal("original attempt replayed or partial success printed", exit, out.String())
	}
	if outputs.Load() != 1 || results.Load() != 2 {
		t.Fatal("unexpected replay/request counts", results.Load(), outputs.Load())
	}
}
func TestArtifactSetCLIRequiresKeyBindingAndDestination(t *testing.T) {
	for _, args := range [][]string{{"attempt", "artifact-set", "-socket", "unused"}, {"attempt", "artifact-set", "-socket", "unused", "-id", "x", "-binding", "unused", "-out-dir", "unused", "-public-key", "bad"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 || out.Len() != 0 {
			t.Fatal("argument errors must not receive data", code)
		}
	}
}
