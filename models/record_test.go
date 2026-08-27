package models

import (
	"reflect"
	"strings"
	"testing"

	dnsv2 "codeberg.org/miekg/dns"
	"github.com/DNSControl/dnscontrol/v5/pkg/privatetypes"
)

// TestR53AliasTargetSurvivesRDATAUpdate verifies the provider-side mutation
// pattern: copy the typed RDATA, update it, and store it with SetRDATA.
func TestR53AliasTargetSurvivesRDATAUpdate(t *testing.T) {
	const origin = "example.com"
	const wantTarget = "kyle.example.com."

	dc := MustNewDomainConfig(origin)
	rc, err := dc.NewRecordConfig("kenny", 300, "R53_ALIAS", "A", wantTarget, "false")
	if err != nil {
		t.Fatalf("NewRecordConfig: %v", err)
	}

	if got := rc.AsR53ALIAS().Target; got != wantTarget {
		t.Fatalf("target after construction = %q, want %q", got, wantTarget)
	}

	// Simulate Route53 filling in the zone ID.
	rd := rc.AsR53ALIAS()
	rd.ZoneID = "Z0389923"
	rc.SetRDATA(rd)

	if got := rc.AsR53ALIAS().Target; got != wantTarget {
		t.Errorf("target after SetRDATA = %q, want %q", got, wantTarget)
	}
	if got := rc.AsR53ALIAS().ZoneID; got != "Z0389923" {
		t.Errorf("zone ID after SetRDATA = %q, want %q", got, "Z0389923")
	}
}

// TestAliasToCnameChangeType reproduces the bug where converting an ALIAS to a
// CNAME via ChangeType() (as CLOUDFLAREAPI and other flattening providers do)
// panicked ("FixUp: .RDATA is nil for type CNAME") and/or lost the target.
func TestAliasToCnameChangeType(t *testing.T) {
	const origin = "example.com"
	const wantTarget = "foo.example.com."

	dc := MustNewDomainConfig(origin)
	rc, err := dc.NewRecordConfig("@", 300, "ALIAS", wantTarget)
	if err != nil {
		t.Fatalf("NewRecordConfig: %v", err)
	}

	// A provider converts the apex ALIAS into a CNAME (CNAME flattening).
	rc.ChangeTypeToCNAME(dc, rc.AsALIAS().Target)

	if rc.GetRDATA() == nil {
		t.Fatal("RDATA is nil after FixRD")
	}
	if got := rc.AsCNAME().Target; got != wantTarget {
		t.Errorf("CNAME target = %q, want %q", got, wantTarget)
	}
}

func TestHasRecordTypeName(t *testing.T) {
	dc := MustNewDomainConfig("example.com")
	recs := Records{}
	if recs.HasRecordTypeName("A", "@") {
		t.Errorf("%v: expected (%v) got (%v)\n", recs, false, true)
	}
	recs = append(recs, dc.MustNewRecordConfig("@", 0, dnsv2.TypeA, "1.2.3.4"))
	if !recs.HasRecordTypeName("A", "@") {
		t.Errorf("%v: expected (%v) got (%v)\n", recs, true, false)
	}
	if recs.HasRecordTypeName("AAAA", "@") {
		t.Errorf("%v: expected (%v) got (%v)\n", recs, false, true)
	}
}

func TestKey(t *testing.T) {
	dc := MustNewDomainConfig("example.com")
	tests := []struct {
		rc       *RecordConfig
		expected RecordKey
	}{
		{
			dc.MustNewRecordConfig("@", 0, dnsv2.TypeA, "1.2.3.4"),
			RecordKey{Type: "A", NameFQDN: "example.com"},
		},
		{
			dc.MustNewRecordConfig("@", 0, privatetypes.TypeR53ALIAS, "AAAA", ".", true, ""),
			RecordKey{Type: "R53_ALIAS_AAAA", NameFQDN: "example.com"},
		},
		{
			dc.MustNewRecordConfig("@", 0, privatetypes.TypeAZUREALIAS, "CNAME", "foo.com"),
			RecordKey{Type: "AZURE_ALIAS_CNAME", NameFQDN: "example.com"},
		},
	}
	for i, test := range tests {
		actual := test.rc.Key()
		if test.expected != actual {
			t.Errorf("%d: Expected %s, got %s", i, test.expected, actual)
		}
	}
}

func TestRecordConfig_Copy(t *testing.T) {
	type fields struct {
		Type      string
		Name      string
		SubDomain string
		NameFQDN  string
		TTL       uint32
		Metadata  map[string]string
		Original  any
	}
	tests := []struct {
		name    string
		fields  fields
		want    *RecordConfig
		wantErr bool
	}{
		{
			name: "only",
			fields: fields{
				Type:      "type",
				Name:      "name",
				SubDomain: "sub",
				NameFQDN:  "namef",
				TTL:       12345,
				Metadata:  map[string]string{"me": "ah", "da": "ta"},
			},
			want: &RecordConfig{
				Type:      "type",
				Name:      "name",
				SubDomain: "sub",
				NameFQDN:  "namef",
				// target:    "targette",
				TTL:      12345,
				Metadata: map[string]string{"me": "ah", "da": "ta"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &RecordConfig{
				Type:      tt.fields.Type,
				Name:      tt.fields.Name,
				SubDomain: tt.fields.SubDomain,
				NameFQDN:  tt.fields.NameFQDN,
				TTL:       tt.fields.TTL,
				Metadata:  tt.fields.Metadata,
				Original:  tt.fields.Original,
			}
			got, err := rc.Copy()
			if (err != nil) != tt.wantErr {
				t.Errorf("RecordConfig.Copy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RecordConfig.Copy() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestFixPosition(t *testing.T) {
	tests := []struct {
		name string
		pos  any
		want string
	}{
		{
			name: "empty string",
			pos:  "",
			want: "",
		},
		{
			name: "anonymous position",
			pos:  "at <anonymous>:2904:5",
			want: "[line:2904:5]",
		},
		{
			name: "random string",
			pos:  "alsdjfsljd",
			want: "[alsdjfsljd]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FixPosition(tt.pos.(string))
			if got != tt.want {
				t.Errorf("fixPosition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_makeLabelNameFQDN(t *testing.T) {
	tests := []struct {
		tname string // description of this test case
		// Named input parameters for target function.
		origin string
		name   string
		want   string
	}{
		{"a", "bosun.org", "@", "bosun.org"},
		{"b", "bosun.org", "foo", "foo.bosun.org"},
		{"c", "bosun.org", "bosun.org.", "bosun.org"},
		{"d", "bosun.org", "foo.bosun.org.", "foo.bosun.org"},
	}
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			got := makeLabelNameFQDN(tt.origin, tt.name)
			if got != tt.want {
				t.Errorf("makeNameFQDN(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func Test_makeLabelNameUnicode(t *testing.T) {
	tests := []struct {
		tname string // description of this test case
		// Named input parameters for target function.
		name string
		want string
	}{
		{"a", "foo.com", "foo.com"},
		{"b", "xn--mnchen-3ya.com", "münchen.com"},
	}
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			got, _ := makeLabelNameUnicode(tt.name)
			if got != tt.want {
				t.Errorf("makeNameUnicode(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestToRRv2PrivateType covers the private use types DNSControl declares itself
// (ALIAS and friends). ToRRv2 builds a record by looking the rdata setter up in
// dnsv2.TypeToRDATA, which the dns library generates for its own types only:
// without the registration pkg/privatetypes makes, this dereferences a nil
// function rather than returning a record.
func TestToRRv2PrivateType(t *testing.T) {
	for _, testCase := range []struct {
		rtype string
		zone  string
	}{
		{"ALIAS", "example.com.\t300\tIN\tALIAS\ttarget.example.net."},
		{"AKAMAICDN", "www.example.com.\t300\tIN\tAKAMAICDN\ttarget.example.net."},
		{"R53_ALIAS", "cdn.example.com.\t300\tIN\tR53_ALIAS\tA aws.example.net. false Z1234"},
	} {
		t.Run(testCase.rtype, func(t *testing.T) {
			zp := dnsv2.NewZoneParser(strings.NewReader(testCase.zone+"\n"), "example.com", "test")
			rr, ok := zp.Next()
			if !ok {
				t.Fatalf("parsing %q: %v", testCase.zone, zp.Err())
			}

			dc := MustNewDomainConfig("example.com")
			rec, err := dc.NewRecordConfigForRRv2toRC(dc.LabelFromFQDNWithDot(rr.Header().Name), rr.Header().TTL, dnsv2.RRToType(rr), rr.Data())
			if err != nil {
				t.Fatalf("NewRecordConfigForRRv2toRC: %v", err)
			}

			if got := rec.ToRRv2().String(); got != testCase.zone {
				t.Errorf("ToRRv2 gave %q, want %q", got, testCase.zone)
			}
		})
	}
}
