package serviceupgrade

// sow: pomar-SOW-87. Preserve the permitted owner-derived view without caller I/O.
import (
	"bytes"
	"testing"
)

func TestOwnerCallerProjectionPreservesEvidenceAndCapacity(t *testing.T) {
	rows := []byte(`[{"attempt":"allowed","state":"exited","class":{"name":"allowed"},"future":9007199254740993},{"attempt":"other","state":"exited","class":{"name":"other"}}]`)
	cp := []byte(`{"live":0,"class":{"name":"other","vcpu":1,"memory_bytes":100},"classes":[{"name":"other","vcpu":1,"memory_bytes":100},{"name":"allowed","vcpu":2,"memory_bytes":200}],"host":{"cpu_slots":8,"memory_bytes":800}}`)
	h, cap, err := ownerCallerProjection(rows, cp, "allowed")
	if err != nil {
		t.Fatal(err)
	}
	want, err := history([]byte(`[{"attempt":"allowed","state":"exited","class":{"name":"allowed"},"future":9007199254740993}]`), "allowed")
	if err != nil || h != want {
		t.Fatal("projection lost exact evidence", err)
	}
	wantCap, err := capacityBinding([]byte(`{"live":0,"class":{"name":"other","vcpu":1,"memory_bytes":100},"classes":[{"name":"allowed","vcpu":2,"memory_bytes":200}],"host":{"cpu_slots":8,"memory_bytes":800}}`))
	if err != nil || cap != wantCap {
		t.Fatal("wrong caller capacity projection", err)
	}
	changed, _, err := ownerCallerProjection(bytes.Replace(rows, []byte("9007199254740993"), []byte("9007199254740992"), 1), cp, "allowed")
	if err != nil || changed == h {
		t.Fatal("unknown evidence change lost", err)
	}
	for _, class := range []string{"", "missing"} {
		if _, _, err := ownerCallerProjection(rows, cp, class); err == nil {
			t.Fatal("unbound caller class accepted", class)
		}
	}
}
