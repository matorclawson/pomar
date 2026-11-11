package artifactreturn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

type Output struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type signedResult struct {
	Schema        string  `json:"schema"`
	Mirror        string  `json:"mirror"`
	Ref           string  `json:"ref"`
	Git           bool    `json:"git"`
	ReadOnly      bool    `json:"readonly_source"`
	Attempt       string  `json:"attempt"`
	State         string  `json:"state"`
	ExitCode      *int    `json:"exit_code"`
	HostCondition string  `json:"host_condition"`
	Reason        string  `json:"reason"`
	Host          string  `json:"host"`
	SHA           string  `json:"sha"`
	Image         string  `json:"image_digest"`
	PackageSet    string  `json:"package_set"`
	Rootfs        string  `json:"rootfs_sha256"`
	Command       string  `json:"command_sha256"`
	Caller        *uint32 `json:"started_by_uid"`
	Class         struct {
		Name      string  `json:"name"`
		OutputCap int64   `json:"output_cap_bytes"`
		Artifact  *Policy `json:"artifact_output,omitempty"`
	} `json:"class"`
	Count   int               `json:"artifact_output_count"`
	Outputs []Output          `json:"outputs"`
	Inputs  []json.RawMessage `json:"inputs"`
}

// Expected comes from the receiving owner's reviewed request, not the reply.
type Expected struct {
	Mirror, Ref                                                  string
	SourceGit, ReadOnlySource                                    bool
	Attempt, Class, SourceSHA, ImageDigest, CommandSHA256, KeyID string
	CallerUID                                                    uint32
	PolicySHA256, PackageSet, RootfsSHA256                       string
}

type Verified struct {
	Attempt      string
	Policy       Policy
	Aggregate    int64
	Outputs      []Output
	Total        int64
	ResultSHA256 string
	RawReply     []byte
}

// uniqueJSON rejects ambiguous duplicate/case-alias fields and trailing JSON.
func uniqueJSON(dec *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("artifact: metadata nesting")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("artifact: field")
			}
			// JSON field matching in encoding/json is case-insensitive.
			if !asciiField(key) {
				return fmt.Errorf("artifact: non-ASCII field")
			}
			key = strings.ToLower(key)
			if seen[key] {
				return fmt.Errorf("artifact: duplicate field")
			}
			seen[key] = true
			if err := uniqueJSON(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("artifact: object end")
		}
	case '[':
		for dec.More() {
			if err := uniqueJSON(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("artifact: array end")
		}
	default:
		return fmt.Errorf("artifact: unexpected delimiter")
	}
	return nil
}

func asciiField(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// PolicyDigest binds the independently reviewed policy and aggregate ceiling.
func PolicyDigest(p Policy, aggregate int64) string {
	data, _ := json.Marshal(struct {
		Policy    Policy `json:"policy"`
		Aggregate int64  `json:"aggregate"`
	}{p, aggregate})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Verify authenticates the exact existing pomar.result/v1 bytes, then binds
// identity, explicit limits, exact closed names, lengths, count and digests.
func Verify(reply []byte, key ed25519.PublicKey, want Expected) (Verified, error) {
	var out Verified
	if len(reply) == 0 || len(reply) > MaxResultBytes || len(key) != ed25519.PublicKeySize ||
		!ValidName(want.Mirror) || want.Ref == "" || len(want.Ref) > 256 || !ValidName(want.Attempt) || !ValidName(want.Class) || !commitRE.MatchString(want.SourceSHA) ||
		!imageRE.MatchString(want.ImageDigest) || !shaRE.MatchString(want.PolicySHA256) ||
		!shaRE.MatchString(want.PackageSet) || !shaRE.MatchString(want.RootfsSHA256) || !shaRE.MatchString(want.CommandSHA256) || !shaRE.MatchString(want.KeyID) {
		return out, fmt.Errorf("artifact: invalid receiving binding")
	}
	reply = append([]byte(nil), reply...)
	key = append(ed25519.PublicKey(nil), key...)
	dec := json.NewDecoder(bytes.NewReader(reply))
	if err := uniqueJSON(dec, 0); err != nil {
		return out, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return out, fmt.Errorf("artifact: trailing JSON")
	}
	var envelope struct {
		Result    json.RawMessage `json:"result"`
		Signature string          `json:"signature"`
		KeyID     string          `json:"key_id"`
	}
	if err := json.Unmarshal(reply, &envelope); err != nil {
		return out, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || envelope.KeyID != want.KeyID || !ed25519.Verify(key, envelope.Result, sig) {
		return out, fmt.Errorf("artifact: original result signature or key binding")
	}
	keyID := sha256.Sum256(key)
	if hex.EncodeToString(keyID[:]) != want.KeyID {
		return out, fmt.Errorf("artifact: independent key ID")
	}
	var result signedResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return out, err
	}
	if len(result.Inputs) != 0 {
		return out, fmt.Errorf("artifact: per-run inputs are outside the pinned image/source binding")
	}
	if result.Mirror != want.Mirror || result.Ref != want.Ref || result.Git != want.SourceGit || result.ReadOnly != want.ReadOnlySource || result.Schema != "pomar.result/v1" || result.Attempt != want.Attempt || result.Class.Name != want.Class ||
		result.PackageSet != want.PackageSet || result.Rootfs != want.RootfsSHA256 || result.SHA != want.SourceSHA || result.Image != want.ImageDigest || result.Command != want.CommandSHA256 ||
		result.Host != want.KeyID || result.Caller == nil || *result.Caller != want.CallerUID || result.State != "exited" ||
		result.ExitCode == nil || *result.ExitCode != 0 || result.HostCondition != "" || result.Reason != "" {
		return out, fmt.Errorf("artifact: result identity or execution not accepted")
	}
	p := result.Class.Artifact
	if err := p.Validate(result.Class.OutputCap); err != nil {
		return out, err
	}
	if PolicyDigest(*p, result.Class.OutputCap) != want.PolicySHA256 {
		return out, fmt.Errorf("artifact: independently reviewed policy mismatch")
	}
	if result.Count != len(result.Outputs) || result.Count != len(p.Names) || result.Count > p.MaxFiles {
		return out, fmt.Errorf("artifact: incomplete or excessive count")
	}
	names := map[string]bool{}
	for _, name := range p.Names {
		names[name] = true
	}
	var total int64
	for _, output := range result.Outputs {
		if !names[output.Name] || output.Status != "ok" || output.Bytes < 0 || output.Bytes > p.PerFileBytes ||
			output.Bytes > result.Class.OutputCap-total || !shaRE.MatchString(output.SHA256) {
			return out, fmt.Errorf("artifact: output identity, count or byte limit")
		}
		delete(names, output.Name)
		total += output.Bytes
	}
	if len(names) != 0 {
		return out, fmt.Errorf("artifact: missing output")
	}
	hash := sha256.Sum256(envelope.Result)
	return Verified{Attempt: result.Attempt, Policy: *p, Aggregate: result.Class.OutputCap, Outputs: result.Outputs,
		Total: total, ResultSHA256: hex.EncodeToString(hash[:]), RawReply: append([]byte(nil), reply...)}, nil
}

// Fetch must honor ctx during acquisition and unblock a read when closed.
// The HTTP-backed integration must use a context-bound request, never retry.
type Fetch func(context.Context, string) (io.ReadCloser, error)
type FreeBytes func(*os.Root) (int64, error)

func freeBytes(root *os.Root) (int64, error) {
	f, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &fs); err != nil {
		return 0, err
	}
	// Bound the conversion rather than overflowing on a huge filesystem.
	if fs.Bsize <= 0 || uint64(fs.Bavail) > uint64(^uint64(0)>>1)/uint64(fs.Bsize) {
		return 0, fmt.Errorf("artifact: filesystem counters")
	}
	return int64(fs.Bavail) * int64(fs.Bsize), nil
}

func writeNew(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Receive returns a confined staging path ONLY after every named byte has
// passed signed length/hash checks and every file/directory has been synced.
// A failed directory is fenced and is never returned as accepted. No on-disk
// success marker is written, and no pathname
// is a discoverable success API: the integrating caller must
// publish success only after this function returns nil, and must reconcile a
// lost acknowledgement without rerunning this one-use attempt. The parent is
// the receiver's private trust boundary, not protection from hostile same-UID
// processes. A free-space check is a preflight, not a filesystem reservation.
func Receive(ctx context.Context, parent *os.Root, reply []byte, key ed25519.PublicKey, want Expected,
	fetch Fetch, available FreeBytes) (ready string, err error) {
	return receive(ctx, parent, reply, key, want, fetch, available, syncDirectory)
}

// The sync operation is passed internally so ordering and filesystem refusal
// can be tested deterministically; production always uses real directory Sync.
func syncDirectory(root *os.Root) error {
	folder, err := root.Open(".")
	if err != nil {
		return err
	}
	err = folder.Sync()
	closeErr := folder.Close()
	return errors.Join(err, closeErr)
}

func receive(ctx context.Context, parent *os.Root, reply []byte, key ed25519.PublicKey, want Expected,
	fetch Fetch, available FreeBytes, syncDir func(*os.Root) error) (ready string, err error) {
	if fetch == nil {
		return "", fmt.Errorf("artifact: missing bounded fetch implementation")
	}
	v, err := Verify(reply, key, want)
	if err != nil {
		return "", err
	}
	if available == nil {
		available = freeBytes
	}
	free, err := available(parent)
	if err != nil || free < v.Aggregate {
		return "", fmt.Errorf("artifact: full class ceiling does not fit receiving filesystem")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(v.Policy.TransferSeconds)*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	pending := ".partial-" + want.Attempt
	if err := parent.Mkdir(pending, 0o700); err != nil {
		return "", err
	}
	stage, err := parent.OpenRoot(pending)
	if err != nil {
		return "", err
	}
	defer stage.Close()
	defer func() {
		if err != nil {
			markerErr := writeNew(stage, "FAILED.json", []byte("{\"state\":\"FAILED_NO_REPLAY\"}\n"))
			err = errors.Join(err, markerErr, syncDir(stage), syncDir(parent))
		}
	}()
	if err = writeNew(stage, "ORIGINAL-RESULT.json", v.RawReply); err != nil {
		return "", err
	}

	// Persist both original evidence and the one-use attempt claim BEFORE any
	// fetch. A failed sync refuses transfer; never unlink an uncertain claim.
	if err = syncDir(stage); err != nil {
		return "", err
	}
	if err = syncDir(parent); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	var total int64
	for _, output := range v.Outputs {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		var source io.ReadCloser
		source, err = fetch(ctx, output.Name)
		if err != nil {
			return "", err
		}
		stopClose := context.AfterFunc(ctx, func() { _ = source.Close() })
		var file *os.File
		file, err = stage.OpenFile(output.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
		if err != nil {
			stopClose()
			_ = source.Close()
			return "", err
		}
		hash := sha256.New()
		var count int64
		buffer := make([]byte, 64<<10)
		for {
			if err = ctx.Err(); err != nil {
				break
			}
			left := output.Bytes - count
			readSize := int64(len(buffer))
			if readSize > left+1 {
				readSize = left + 1
			}
			var n int
			var readErr error
			n, readErr = source.Read(buffer[:int(readSize)])
			// Cancellation may unblock Read with buffered bytes, even alongside
			// EOF or another error. Refuse that fragment before any write.
			if err = ctx.Err(); err != nil {
				break
			}
			// An overrun byte is never written, even temporarily.
			if int64(n) > left || int64(n) > v.Policy.PerFileBytes-count || int64(n) > v.Aggregate-total {
				err = fmt.Errorf("artifact: stream overrun")
				break
			}
			if n > 0 {
				var written int
				written, err = file.Write(buffer[:n])
				if err != nil || written != n {
					if err == nil {
						err = io.ErrShortWrite
					}
					break
				}
				hash.Write(buffer[:n])
				count += int64(n)
				total += int64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				err = readErr
				break
			}
			if n == 0 {
				err = io.ErrNoProgress
				break
			}
		}
		stopClose()
		closeErr := source.Close()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil && (count != output.Bytes || hex.EncodeToString(hash.Sum(nil)) != output.SHA256) {
			err = fmt.Errorf("artifact: truncation or digest mismatch")
		}
		if err == nil {
			err = file.Sync()
		}
		fileCloseErr := file.Close()
		if err == nil {
			err = fileCloseErr
		}
		if err != nil {
			return "", err
		}
	}
	if total != v.Total {
		return "", fmt.Errorf("artifact: aggregate mismatch")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = syncDir(stage); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = syncDir(parent); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	return pending, nil
}
