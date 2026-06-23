package main

import (
	"math"
	"testing"
)

func TestEntropyBounds(t *testing.T) {
	if e := entropy([]byte{}); e != 0.0 {
		t.Fatalf("empty entropy = %v, want 0", e)
	}
	if e := entropy([]byte("AAAA")); e != 0.0 {
		t.Fatalf("uniform entropy = %v, want 0", e)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if e := entropy(all); math.Abs(e-8.0) > 1e-3 {
		t.Fatalf("max entropy = %v, want ~8", e)
	}
}

func TestFiletype(t *testing.T) {
	cases := map[string]string{
		"MZ\x90\x00":       "pe",
		"\x7fELFxxxx":      "elf",
		"%PDF-1.7":         "pdf",
		"plain ascii text": "text",
	}
	for in, want := range cases {
		if got := filetype([]byte(in)); got != want {
			t.Errorf("filetype(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanRansom(t *testing.T) {
	note := []byte("your files have been encrypted, send bitcoin to our BTC wallet to decrypt")
	ms := scanRules(note)
	found := false
	for _, m := range ms {
		if m.Rule == "Ransom_Note" && m.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Ransom_Note(critical) not fired: %+v", ms)
	}
	if maxSeverity(ms) != "critical" {
		t.Fatalf("maxSeverity = %q, want critical", maxSeverity(ms))
	}
}

func TestScanPowershell(t *testing.T) {
	blob := []byte("powershell -enc IEX DownloadString FromBase64String")
	ms := scanRules(blob)
	found := false
	for _, m := range ms {
		if m.Rule == "Embedded_PowerShell" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Embedded_PowerShell not fired: %+v", ms)
	}
}

func TestScanClean(t *testing.T) {
	if ms := scanRules([]byte("just ordinary text")); len(ms) != 0 {
		t.Fatalf("clean text fired rules: %+v", ms)
	}
}

func TestEicar(t *testing.T) {
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	ms := scanRules(eicar)
	found := false
	for _, m := range ms {
		if m.Rule == "EICAR_Test_File" {
			found = true
		}
	}
	if !found {
		t.Fatalf("EICAR not fired: %+v", ms)
	}
}
