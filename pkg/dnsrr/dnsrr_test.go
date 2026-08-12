package dnsrr

import (
	"testing"

	dnsv1 "github.com/miekg/dns"
)

// TestRRtoRCTxtFormatTypes covers the types whose rdata is a list of
// character-strings, like TXT. helperRRtoRC fills them all with SetTargetTXTs,
// which asserts on RecordConfig.HasFormatIdenticalToTXT: a type missing from
// that list makes this panic rather than return an error.
func TestRRtoRCTxtFormatTypes(t *testing.T) {
	for _, rdata := range []string{
		`TXT "a piece of text"`,
		`SPF "v=spf1 -all"`,
		`AVC "app-name=example"`,
		`NINFO "this is a zone status"`,
	} {
		t.Run(rdata, func(t *testing.T) {
			line := "sample.example.com. 300 IN " + rdata

			rr, err := dnsv1.NewRR(line)
			if err != nil {
				t.Fatalf("NewRR(%q): %v", line, err)
			}

			rc, err := RRtoRC(rr, "example.com")
			if err != nil {
				t.Fatalf("RRtoRC: %v", err)
			}

			if rc.GetTargetTXTJoined() == "" {
				t.Errorf("the target is empty, the record was %q", rr.String())
			}

			// ToRR() reads those fields back with GetTargetTXTSegmented, so the
			// record must come back unchanged.
			if got, want := rc.ToRR().String(), rr.String(); got != want {
				t.Errorf("the round trip altered the record: got %q, want %q", got, want)
			}
		})
	}
}

// TestRRtoRCTxtFormatTypesJoined checks the several character-strings of such a
// record are concatenated into the single target a RecordConfig holds, the way
// DNSControl stores a TXT.
func TestRRtoRCTxtFormatTypesJoined(t *testing.T) {
	for _, rdata := range []string{
		`TXT "part one " "part two"`,
		`AVC "part one " "part two"`,
		`NINFO "part one " "part two"`,
	} {
		t.Run(rdata, func(t *testing.T) {
			rr, err := dnsv1.NewRR("sample.example.com. 300 IN " + rdata)
			if err != nil {
				t.Fatalf("NewRR: %v", err)
			}

			rc, err := RRtoRC(rr, "example.com")
			if err != nil {
				t.Fatalf("RRtoRC: %v", err)
			}

			if got, want := rc.GetTargetTXTJoined(), "part one part two"; got != want {
				t.Errorf("the target is %q, want %q", got, want)
			}
		})
	}
}
