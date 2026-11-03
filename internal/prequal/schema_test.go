package prequal_test

import (
	"testing"

	"github.com/zeroemployeeorg/pomar/internal/prequal"
	"github.com/zeroemployeeorg/pomar/internal/seatdecl"
)

// seat profile/up compile only declarations and their class catalogue. Even a
// qualification result reduced to its schema is refused by both parsers, so
// it cannot become a launch input by losing its other observation fields.
func TestOrdinarySeatInputsRefuseQualificationSchemas(t *testing.T) {
	for _, schema := range []string{prequal.PlanSchema, prequal.ResultSchema} {
		raw := []byte(`{"schema":"` + schema + `"}`)
		if _, _, err := seatdecl.Parse(raw); err == nil {
			t.Fatal("qualification accepted as declaration", schema)
		}
		if _, err := seatdecl.ParseClasses(raw); err == nil {
			t.Fatal("qualification accepted as class catalogue", schema)
		}
	}
}
