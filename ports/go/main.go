// yararun — Go port of the file-intelligence + triage-scan core.
//
// Mirrors the reference Python CLI's two read-only commands:
//
//	yararun-go info  <file>   -> entropy / filetype / md5 / sha1 / sha256
//	yararun-go scan  <file>   -> info + bundled triage string rules that fired
//
// Single binary, zero third-party deps. Passive/offline by design: it only
// reads the bytes you hand it — it never executes, modifies, or transmits.
// Defensive / authorized-use only. JSON shape matches the Python reference.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
)

const toolVersion = "2.0.0"

// rule is a literal-substring triage signature: it fires when at least `min`
// of its needles are present. This is the literal-string subset of the Python
// engine's bundled DEFAULT_RULES (the full engine adds hex/regex/xor/conditions).
type rule struct {
	name     string
	severity string
	needles  []string
	min      int
}

var rules = []rule{
	{"Embedded_PowerShell", "high",
		[]string{"powershell", "-enc", "-EncodedCommand", "FromBase64String",
			"DownloadString", "IEX", "Invoke-Expression", "hidden", "bypass"}, 3},
	{"JS_Eval_Dropper", "high",
		[]string{"eval(", "unescape(", "fromCharCode", "atob(", "document.write"}, 3},
	{"Ransom_Note", "critical",
		[]string{"your files have been encrypted", "decrypt", "bitcoin",
			"BTC wallet", "pay the ransom", "private key"}, 3},
	{"Cryptominer_Config", "high",
		[]string{"stratum+tcp://", "xmrig", "minerd", "pool.minexmr",
			"donate-level", "cryptonight"}, 2},
	{"Shell_Reverse_Connect", "critical",
		[]string{"nc -e", "ncat -e", "bash -i >&", "/dev/tcp/",
			"socket.socket", "subprocess.call"}, 2},
	{"Credential_Theft", "high",
		[]string{"Login Data", "key3.db", "logins.json", "wallet.dat",
			"shadow", "SAM\\SAM"}, 2},
	{"Persistence_Registry_Runkey", "high",
		[]string{"CurrentVersion\\Run", "schtasks /create", "sc create",
			"Start Menu\\Programs\\Startup"}, 1},
	{"UPX_Packed", "medium", []string{"UPX0", "UPX1", "UPX!"}, 2},
	{"EICAR_Test_File", "low",
		[]string{"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"}, 1},
}

// magic maps a file's leading bytes to a coarse type label.
var magic = []struct {
	sig   []byte
	label string
}{
	{[]byte{0x4D, 0x5A}, "pe"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "elf"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "macho"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "macho"},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "macho-fat/java-class"},
	{[]byte("PK\x03\x04"), "zip/office/jar"},
	{[]byte("%PDF"), "pdf"},
	{[]byte{0x89, 0x50, 0x4E, 0x47}, "png"},
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0.0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	ent := 0.0
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			ent -= p * math.Log2(p)
		}
	}
	return math.Round(ent*10000) / 10000
}

func filetype(b []byte) string {
	for _, m := range magic {
		if len(b) >= len(m.sig) && string(b[:len(m.sig)]) == string(m.sig) {
			return m.label
		}
	}
	if len(b) > 0 {
		sample := b
		if len(sample) > 4096 {
			sample = sample[:4096]
		}
		printable := 0
		for _, c := range sample {
			if (c >= 9 && c <= 13) || (c >= 32 && c < 127) {
				printable++
			}
		}
		if float64(printable)/float64(len(sample)) > 0.92 {
			return "text"
		}
	}
	return "data"
}

type match struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}

func scanRules(b []byte) []match {
	text := string(b)
	var out []match
	for _, r := range rules {
		hits := 0
		for _, n := range r.needles {
			if strings.Contains(text, n) {
				hits++
			}
		}
		if hits >= r.min {
			out = append(out, match{r.name, r.severity})
		}
	}
	return out
}

func maxSeverity(ms []match) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	for _, s := range order {
		for _, m := range ms {
			if m.Severity == s {
				return s
			}
		}
	}
	return "info"
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: yararun-go <info|scan> <file>")
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}
	cmd, path := os.Args[1], os.Args[2]
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", path, err)
		os.Exit(2)
	}
	info := map[string]any{
		"tool":     "yararun",
		"version":  toolVersion,
		"target":   path,
		"size":     len(b),
		"filetype": filetype(b),
		"entropy":  entropy(b),
		"md5":      fmt.Sprintf("%x", md5.Sum(b)),
		"sha1":     fmt.Sprintf("%x", sha1.Sum(b)),
		"sha256":   fmt.Sprintf("%x", sha256.Sum256(b)),
	}
	switch cmd {
	case "info":
	case "scan":
		ms := scanRules(b)
		if ms == nil {
			ms = []match{}
		}
		info["matches"] = ms
		info["match_count"] = len(ms)
		info["max_severity"] = maxSeverity(ms)
	default:
		usage()
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(out))
	if cmd == "scan" && len(scanRules(b)) > 0 {
		os.Exit(1) // actionable findings -> non-zero, like the Python CLI
	}
}
