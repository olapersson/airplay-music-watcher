package mdns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseAirplayFlagsEntry(t *testing.T) {
	entry := parseAirplayFlagsEntry(
		"Living Room._airplay._tcp.local.",
		[]string{"model=SOUNDFORM AirPlay2 Adapter", "flags=0xc04"},
	)
	if entry == nil {
		t.Fatal("expected an airplay flags entry")
	}
	if entry.DeviceName != "Living Room" {
		t.Fatalf("unexpected device name: %q", entry.DeviceName)
	}
	if entry.Flags != 0xc04 {
		t.Fatalf("unexpected flags: %#x", entry.Flags)
	}
}

func TestParseAirplayFlagsEntryUnescapesDeviceName(t *testing.T) {
	entry := parseAirplayFlagsEntry(
		"Living\\ Room\\ \\(2\\)._airplay._tcp.local.",
		[]string{"flags=0x18644"},
	)
	if entry == nil {
		t.Fatal("expected an airplay flags entry")
	}
	if entry.DeviceName != "Living Room (2)" {
		t.Fatalf("unexpected device name: %q", entry.DeviceName)
	}
}

func TestParseAirplayFlagsEntryIgnoresNonAirplayRecords(t *testing.T) {
	entry := parseAirplayFlagsEntry(
		"_airplay._tcp.local.",
		[]string{"flags=0xc04"},
	)
	if entry != nil {
		t.Fatal("expected no entry for service-level record")
	}
}

func TestParseAirplayFlagsEntryIgnoresMissingFlags(t *testing.T) {
	entry := parseAirplayFlagsEntry(
		"Living Room._airplay._tcp.local.",
		[]string{"model=SOUNDFORM AirPlay2 Adapter"},
	)
	if entry != nil {
		t.Fatal("expected no entry when flags are missing")
	}
}

func TestTXTRecordNameIsUsedDirectly(t *testing.T) {
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name: "Living\\ Room._airplay._tcp.local.",
		},
		Txt: []string{"flags=0x18644"},
	}

	entry := parseAirplayFlagsEntry(txt.Hdr.Name, txt.Txt)
	if entry == nil {
		t.Fatal("expected an entry from TXT record name")
	}
	if entry.DeviceName != "Living Room" {
		t.Fatalf("unexpected device name: %q", entry.DeviceName)
	}
	if entry.Flags != 0x18644 {
		t.Fatalf("unexpected flags: %#x", entry.Flags)
	}
}
