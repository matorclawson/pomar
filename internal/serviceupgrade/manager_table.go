package serviceupgrade

// sow: pomar-SOW-87. Exact schema recovery; never downgrade-transform a table.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zeroemployeeorg/pomar/internal/manager"
)

const maxManagerTable = 64 << 20

func canonical(raw []byte) ([]byte, error) {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // Unknown evidence integers must never pass through float64.
	if uniqueJSON(raw) != nil || d.Decode(&v) != nil {
		return nil, fmt.Errorf("invalid bounded observation")
	}
	return json.Marshal(v)
}
func history(raw []byte, class string) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' || uniqueJSON(raw) != nil {
		return "", fmt.Errorf("ambiguous history")
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return "", fmt.Errorf("history not a list")
	}
	seen := map[string]bool{}
	var preserved []json.RawMessage
	for _, raw := range entries {
		var e manager.Entry
		if json.Unmarshal(raw, &e) != nil || e.Attempt == "" || seen[e.Attempt] || !e.Terminal() {
			return "", fmt.Errorf("live, duplicate or malformed attempt; upgrade refused")
		}
		if class != "" && e.Class.Name != class {
			return "", fmt.Errorf("caller history escaped fixed class")
		}
		seen[e.Attempt] = true
		b, err := canonical(raw)
		if err != nil {
			return "", err
		}
		preserved = append(preserved, b)
	}
	// Manager list is ordered; keep that order and every original field.
	b, _ := json.Marshal(preserved)
	return digest(b), nil
}

func managerTableHistory(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > maxManagerTable || uniqueJSON(raw) != nil {
		return "", fmt.Errorf("invalid manager table")
	}
	payload := bytes.TrimSpace(raw)
	if len(payload) == 0 {
		return "", fmt.Errorf("empty manager table")
	}
	if payload[0] == '{' {
		var envelope map[string]json.RawMessage
		var schema string
		if json.Unmarshal(payload, &envelope) != nil || len(envelope) != 2 || json.Unmarshal(envelope["schema"], &schema) != nil || schema != "pomar.manager-table/v2" {
			return "", fmt.Errorf("unsupported manager table schema")
		}
		payload = envelope["entries"]
	}
	return history(payload, "")
}

func archiveManagerTable(source, archive string, pin FilePin, ownerUID, archiveUID uint32) error {
	if !validFile(pin, maxManagerTable) {
		return fmt.Errorf("manager table binding required")
	}
	raw, err := pinnedOwnedFile(source, pin, ownerUID)
	if err != nil {
		return err
	}
	if _, err := managerTableHistory(raw); err != nil {
		return err
	}
	if err := durableWriteOwned(archive, raw, 0600, archiveUID); err != nil {
		return err
	}
	_, err = pinnedOwnedFile(archive, pin, archiveUID)
	return err
}

// The caller must first prove every manager/helper writer absent. Semantic
// equality alone is insufficient while a target process can still write.
func restoreManagerTable(target, archive string, pin FilePin, ownerUID, archiveUID uint32, originalHistory string) error {
	raw, err := managerTableRecoveryBytes(target, archive, pin, ownerUID, archiveUID, originalHistory)
	if err != nil {
		return err
	}
	if err := durableWriteOwned(target, raw, os.FileMode(0600), ownerUID); err != nil {
		return err
	}
	_, err = pinnedOwnedFile(target, pin, ownerUID)
	return err
}

// Inspect all recovery inputs before any replacement effect.
func managerTableRecoveryBytes(target, archive string, pin FilePin, ownerUID, archiveUID uint32, originalHistory string) ([]byte, error) {
	raw, err := pinnedOwnedFile(archive, pin, archiveUID)
	if err != nil {
		return nil, err
	}
	archivedHistory, err := managerTableHistory(raw)
	if err != nil || archivedHistory != originalHistory {
		return nil, fmt.Errorf("archived table history differs")
	}
	current, err := readFile(target, maxManagerTable, ownerUID)
	if err != nil {
		return nil, err
	}
	currentHistory, err := managerTableHistory(current)
	if err != nil || currentHistory != originalHistory {
		return nil, fmt.Errorf("manager table changed since upgrade; retain current obligations")
	}
	return raw, nil
}
