package serviceupgrade

// sow: pomar-SOW-87. Owner evidence is labelled a projection, never a caller GET.
import (
	"encoding/json"
	"fmt"

	resources "github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/manager"
)

func ownerCallerProjection(rows, rawCapacity []byte, class string) (string, string, error) {
	if class == "" {
		return "", "", fmt.Errorf("fixed caller class required")
	}
	if _, err := history(rows, ""); err != nil {
		return "", "", err
	}
	var all []json.RawMessage
	if err := json.Unmarshal(rows, &all); err != nil {
		return "", "", err
	}
	selected := []json.RawMessage{}
	for _, row := range all {
		var e manager.Entry
		if err := json.Unmarshal(row, &e); err != nil {
			return "", "", err
		}
		name := e.Class.Name
		if name == "" {
			name = resources.CI.Name
		}
		if name == class {
			selected = append(selected, row)
		}
	}
	b, err := json.Marshal(selected)
	if err != nil {
		return "", "", err
	}
	h, err := history(b, "") // Legacy default-class rows are preserved intact.
	if err != nil {
		return "", "", err
	}
	if _, err := capacityBinding(rawCapacity); err != nil {
		return "", "", err
	}
	var cp manager.Capacity
	if err := json.Unmarshal(rawCapacity, &cp); err != nil {
		return "", "", err
	}
	classes := []resources.Class{}
	for _, c := range cp.Classes {
		if c.Name == class {
			classes = append(classes, c)
		}
	}
	if len(classes) != 1 {
		return "", "", fmt.Errorf("caller class missing or duplicated")
	}
	cp.Classes = classes
	b, err = json.Marshal(cp)
	if err != nil {
		return "", "", err
	}
	c, err := capacityBinding(b)
	return h, c, err
}

func capacityBinding(raw []byte) (string, error) {
	var cp manager.Capacity
	if uniqueJSON(raw) != nil || json.Unmarshal(raw, &cp) != nil || cp.Live != 0 || cp.Class.Name == "" || cp.Class.VCPU < 1 || cp.Class.MemoryBytes < 1 || len(cp.Classes) == 0 || cp.Host.CPUSlots < 1 || cp.Host.MemoryBytes < 1 {
		return "", fmt.Errorf("non-idle or malformed capacity")
	}
	// Space, live count and drain are observations, not installation identity.
	b, _ := json.Marshal(struct {
		Class   any `json:"class"`
		Classes any `json:"classes"`
		Host    any `json:"host"`
	}{cp.Class, cp.Classes, cp.Host})
	return digest(b), nil
}
