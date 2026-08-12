package dnsrr

import (
	"strings"
	"testing"

	dnsv2 "codeberg.org/miekg/dns"
	"github.com/DNSControl/dnscontrol/v5/models"
)

// parseOne parses a single record out of a zone file fragment.
func parseOne(t *testing.T, line string) dnsv2.RR {
	t.Helper()
	zp := dnsv2.NewZoneParser(strings.NewReader(line), "example.com", "test")
	rr, ok := zp.Next()
	if !ok {
		t.Fatalf("no record parsed from %q: %v", line, zp.Err())
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parsing %q: %v", line, err)
	}
	return rr
}

// TestRRv2toRCTxtFormatTypes covers the types whose rdata is a list of
// character-strings, like TXT. A single character-string must survive the round
// trip through RecordConfig unchanged, whichever of those types carries it.
func TestRRv2toRCTxtFormatTypes(t *testing.T) {
	for _, rdata := range []string{
		`TXT "a piece of text"`,
		`SPF "v=spf1 -all"`,
		`AVC "app-name=example"`,
		`NINFO "this is a zone status"`,
	} {
		t.Run(rdata, func(t *testing.T) {
			dc := &models.DomainConfig{Name: "example.com"}
			rr := parseOne(t, "sample.example.com. 300 IN "+rdata)

			rc, err := RRv2toRC(dc, rr)
			if err != nil {
				t.Fatalf("RRv2toRC: %v", err)
			}

			if got := rc.GetRDATA().String(); got == "" {
				t.Errorf("the rdata is empty, the record was %q", rr.String())
			}

			if got, want := rc.ToRRv2().String(), rr.String(); got != want {
				t.Errorf("the round trip altered the record: got %q, want %q", got, want)
			}
		})
	}
}

// TestRRv2toRCTxtFormatTypesJoined checks that the several character-strings of
// a TXT-shaped record are concatenated into the single value DNSControl stores.
// AVC shares TXT's rdata type, so it is joined too; NINFO has its own rdata and
// keeps its character-strings apart.
func TestRRv2toRCTxtFormatTypesJoined(t *testing.T) {
	for _, tc := range []struct {
		rdata string
		want  string
	}{
		{`TXT "part one " "part two"`, `"part one part two"`},
		{`AVC "part one " "part two"`, `"part one part two"`},
		{`NINFO "part one " "part two"`, `"part one " "part two"`},
	} {
		t.Run(tc.rdata, func(t *testing.T) {
			dc := &models.DomainConfig{Name: "example.com"}
			rr := parseOne(t, "sample.example.com. 300 IN "+tc.rdata)

			rc, err := RRv2toRC(dc, rr)
			if err != nil {
				t.Fatalf("RRv2toRC: %v", err)
			}

			if got := rc.GetRDATA().String(); got != tc.want {
				t.Errorf("the rdata is %q, want %q", got, tc.want)
			}
		})
	}
}
