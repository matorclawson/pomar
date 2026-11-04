package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedissuer"
	"io"
	"os"
	"path/filepath"
)

func trustBytes(record publicRecord) ([]byte, error) {
	if record.KeyID != custodyKeyID {
		return nil, fmt.Errorf("only production key may enter production trust")
	}
	return json.Marshal(struct {
		Schema string `json:"schema"`
		Keys   []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}{Schema: "zeoconnect.pomar-feed-trust/v1", Keys: []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}{{record.KeyID, record.PublicKey}}})
}
func publishTrust(c config, keyRoot *os.Root, base string, out io.Writer) error {
	for _, p := range []string{base, filepath.Join(base, "entries"), filepath.Join(base, "trust"), filepath.Join(base, "rehearsal")} {
		if e := releasefeedissuer.CheckPublicDirectory(p, c.uid); e != nil {
			return e
		}
	}
	var pub bytes.Buffer
	if e := public(c, keyRoot, &pub); e != nil {
		return e
	}
	var record publicRecord
	if json.Unmarshal(pub.Bytes(), &record) != nil {
		return fmt.Errorf("public record decode")
	}
	raw, e := trustBytes(record)
	if e != nil {
		return e
	}
	root, e := os.OpenRoot(filepath.Join(base, "trust"))
	if e != nil {
		return e
	}
	defer root.Close()
	file, e := root.OpenFile(".pending-pomar-feed-trust-v1.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return fmt.Errorf("trust original pending; reconcile")
	}
	n, e := file.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = file.Chmod(0644)
	}
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	// An exclusive hard link installs a complete regular file without replacing
	// any prior trust. Unknown predecessors/pending records remain visible.
	if e := root.Link(".pending-pomar-feed-trust-v1.json", "pomar-feed-trust-v1.json"); e != nil {
		return e
	}
	if e := syncHome(root); e != nil {
		return e
	}
	if e := root.Remove(".pending-pomar-feed-trust-v1.json"); e != nil {
		return e
	}
	if e := syncHome(root); e != nil {
		return e
	}
	f, e := root.Open("pomar-feed-trust-v1.json")
	if e != nil {
		return e
	}
	got, e := io.ReadAll(io.LimitReader(f, 8193))
	ce = f.Close()
	if e != nil || ce != nil || !bytes.Equal(raw, got) {
		return fmt.Errorf("public trust readback mismatch")
	}
	h := sha256.Sum256(raw)
	return json.NewEncoder(out).Encode(map[string]any{"schema": "pomar.feed-trust-publication/v1", "key_id": record.KeyID, "public_key": record.PublicKey, "public_key_sha256": record.Fingerprint, "trust_sha256": hex.EncodeToString(h[:]), "trust_file": filepath.Join(base, "trust", "pomar-feed-trust-v1.json"), "production_trust_adopted": false})
}
