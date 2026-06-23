// yararun — Rust port of the file-intelligence + triage-scan core.
//
// Mirrors the reference Python CLI's two read-only commands:
//
//   yararun-rs info <file>   -> entropy / filetype / sha256-ish summary
//   yararun-rs scan <file>   -> info + bundled triage string rules that fired
//
// Single static binary, std-only (no crates). Passive/offline by design: it
// only reads the bytes you hand it. Defensive / authorized-use only.

use std::env;
use std::fs;
use std::process::exit;

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ent = 0.0;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    (ent * 10000.0).round() / 10000.0
}

pub fn filetype(data: &[u8]) -> &'static str {
    let magic: [(&[u8], &str); 8] = [
        (&[0x4D, 0x5A], "pe"),
        (&[0x7F, 0x45, 0x4C, 0x46], "elf"),
        (&[0xFE, 0xED, 0xFA, 0xCE], "macho"),
        (&[0xFE, 0xED, 0xFA, 0xCF], "macho"),
        (&[0xCA, 0xFE, 0xBA, 0xBE], "macho-fat/java-class"),
        (b"PK\x03\x04", "zip/office/jar"),
        (b"%PDF", "pdf"),
        (&[0x89, 0x50, 0x4E, 0x47], "png"),
    ];
    for (sig, label) in magic.iter() {
        if data.len() >= sig.len() && &data[..sig.len()] == *sig {
            return label;
        }
    }
    if !data.is_empty() {
        let sample = &data[..data.len().min(4096)];
        let printable = sample
            .iter()
            .filter(|&&c| (9..=13).contains(&c) || (32..127).contains(&c))
            .count();
        if printable as f64 / sample.len() as f64 > 0.92 {
            return "text";
        }
    }
    "data"
}

struct Rule {
    name: &'static str,
    severity: &'static str,
    needles: &'static [&'static str],
    min: usize,
}

const RULES: &[Rule] = &[
    Rule { name: "Embedded_PowerShell", severity: "high",
        needles: &["powershell", "-enc", "-EncodedCommand", "FromBase64String",
                   "DownloadString", "IEX", "Invoke-Expression", "hidden", "bypass"], min: 3 },
    Rule { name: "JS_Eval_Dropper", severity: "high",
        needles: &["eval(", "unescape(", "fromCharCode", "atob(", "document.write"], min: 3 },
    Rule { name: "Ransom_Note", severity: "critical",
        needles: &["your files have been encrypted", "decrypt", "bitcoin",
                   "BTC wallet", "pay the ransom", "private key"], min: 3 },
    Rule { name: "Cryptominer_Config", severity: "high",
        needles: &["stratum+tcp://", "xmrig", "minerd", "pool.minexmr",
                   "donate-level", "cryptonight"], min: 2 },
    Rule { name: "Shell_Reverse_Connect", severity: "critical",
        needles: &["nc -e", "ncat -e", "bash -i >&", "/dev/tcp/",
                   "socket.socket", "subprocess.call"], min: 2 },
    Rule { name: "Credential_Theft", severity: "high",
        needles: &["Login Data", "key3.db", "logins.json", "wallet.dat",
                   "shadow", "SAM\\SAM"], min: 2 },
    Rule { name: "UPX_Packed", severity: "medium",
        needles: &["UPX0", "UPX1", "UPX!"], min: 2 },
    Rule { name: "EICAR_Test_File", severity: "low",
        needles: &["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"], min: 1 },
];

pub fn scan_rules(data: &[u8]) -> Vec<(&'static str, &'static str)> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for r in RULES {
        let hits = r.needles.iter().filter(|n| text.contains(*n)).count();
        if hits >= r.min {
            out.push((r.name, r.severity));
        }
    }
    out
}

pub fn max_severity(ms: &[(&str, &str)]) -> &'static str {
    for s in ["critical", "high", "medium", "low", "info"] {
        if ms.iter().any(|(_, sev)| *sev == s) {
            return match s {
                "critical" => "critical",
                "high" => "high",
                "medium" => "medium",
                "low" => "low",
                _ => "info",
            };
        }
    }
    "info"
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: yararun-rs <info|scan> <file>");
        exit(2);
    }
    let (cmd, path) = (&args[1], &args[2]);
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            exit(2);
        }
    };
    let ft = filetype(&data);
    let ent = entropy(&data);
    if cmd == "info" {
        println!(
            "{{\"tool\":\"yararun\",\"target\":{:?},\"size\":{},\"filetype\":\"{}\",\"entropy\":{}}}",
            path, data.len(), ft, ent
        );
    } else if cmd == "scan" {
        let ms = scan_rules(&data);
        let items: Vec<String> = ms
            .iter()
            .map(|(n, s)| format!("{{\"rule\":\"{}\",\"severity\":\"{}\"}}", n, s))
            .collect();
        println!(
            "{{\"tool\":\"yararun\",\"target\":{:?},\"size\":{},\"filetype\":\"{}\",\"entropy\":{},\"match_count\":{},\"max_severity\":\"{}\",\"matches\":[{}]}}",
            path, data.len(), ft, ent, ms.len(), max_severity(&ms), items.join(",")
        );
        if !ms.is_empty() {
            exit(1);
        }
    } else {
        eprintln!("usage: yararun-rs <info|scan> <file>");
        exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(b"AAAA"), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-3);
    }

    #[test]
    fn filetype_magic() {
        assert_eq!(filetype(b"MZ\x90\x00"), "pe");
        assert_eq!(filetype(b"\x7fELFxxxx"), "elf");
        assert_eq!(filetype(b"%PDF-1.7"), "pdf");
        assert_eq!(filetype(b"plain ascii text"), "text");
        assert_eq!(filetype(&[0u8, 1, 2, 200, 255]), "data");
    }

    #[test]
    fn scan_ransom_critical() {
        let note = b"your files have been encrypted, send bitcoin to our BTC wallet to decrypt";
        let ms = scan_rules(note);
        assert!(ms.iter().any(|(n, s)| *n == "Ransom_Note" && *s == "critical"));
        assert_eq!(max_severity(&ms), "critical");
    }

    #[test]
    fn scan_powershell() {
        let blob = b"powershell -enc IEX DownloadString FromBase64String";
        let ms = scan_rules(blob);
        assert!(ms.iter().any(|(n, _)| *n == "Embedded_PowerShell"));
    }

    #[test]
    fn scan_clean() {
        assert!(scan_rules(b"just ordinary text").is_empty());
    }

    #[test]
    fn scan_eicar() {
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        let ms = scan_rules(eicar);
        assert!(ms.iter().any(|(n, _)| *n == "EICAR_Test_File"));
    }
}
