#!/usr/bin/env node
// yararun — JavaScript/Node port of the file-intelligence + triage-scan core.
//
// Mirrors the reference Python CLI's two read-only commands:
//
//   node index.js info <file>   -> entropy / filetype / md5 / sha1 / sha256
//   node index.js scan <file>   -> info + bundled triage string rules that fired
//
// Std-only (node:crypto, node:fs). Passive/offline by design: it only reads the
// bytes you hand it. Defensive / authorized-use only. JSON shape matches Python.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { argv, exit, stderr } from "node:process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export const TOOL_VERSION = "2.0.0";

export function entropy(buf) {
  if (!buf.length) return 0.0;
  const freq = new Array(256).fill(0);
  for (const b of buf) freq[b]++;
  const n = buf.length;
  let ent = 0.0;
  for (const c of freq) {
    if (c) {
      const p = c / n;
      ent -= p * Math.log2(p);
    }
  }
  return Math.round(ent * 10000) / 10000;
}

const MAGIC = [
  [[0x4d, 0x5a], "pe"],
  [[0x7f, 0x45, 0x4c, 0x46], "elf"],
  [[0xfe, 0xed, 0xfa, 0xce], "macho"],
  [[0xfe, 0xed, 0xfa, 0xcf], "macho"],
  [[0xca, 0xfe, 0xba, 0xbe], "macho-fat/java-class"],
  [[0x50, 0x4b, 0x03, 0x04], "zip/office/jar"],
  [[0x25, 0x50, 0x44, 0x46], "pdf"],
  [[0x89, 0x50, 0x4e, 0x47], "png"],
];

export function filetype(buf) {
  for (const [sig, label] of MAGIC) {
    if (buf.length >= sig.length && sig.every((b, i) => buf[i] === b)) return label;
  }
  if (buf.length) {
    const sample = buf.subarray(0, 4096);
    let printable = 0;
    for (const c of sample) if ((c >= 9 && c <= 13) || (c >= 32 && c < 127)) printable++;
    if (printable / sample.length > 0.92) return "text";
  }
  return "data";
}

const RULES = [
  ["Embedded_PowerShell", "high",
    ["powershell", "-enc", "-EncodedCommand", "FromBase64String",
      "DownloadString", "IEX", "Invoke-Expression", "hidden", "bypass"], 3],
  ["JS_Eval_Dropper", "high",
    ["eval(", "unescape(", "fromCharCode", "atob(", "document.write"], 3],
  ["Ransom_Note", "critical",
    ["your files have been encrypted", "decrypt", "bitcoin",
      "BTC wallet", "pay the ransom", "private key"], 3],
  ["Cryptominer_Config", "high",
    ["stratum+tcp://", "xmrig", "minerd", "pool.minexmr",
      "donate-level", "cryptonight"], 2],
  ["Shell_Reverse_Connect", "critical",
    ["nc -e", "ncat -e", "bash -i >&", "/dev/tcp/",
      "socket.socket", "subprocess.call"], 2],
  ["Credential_Theft", "high",
    ["Login Data", "key3.db", "logins.json", "wallet.dat",
      "shadow", "SAM\\SAM"], 2],
  ["UPX_Packed", "medium", ["UPX0", "UPX1", "UPX!"], 2],
  ["EICAR_Test_File", "low", ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"], 1],
];

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export function scanRules(buf) {
  const text = buf.toString("latin1");
  const out = [];
  for (const [name, severity, needles, min] of RULES) {
    const hits = needles.filter((n) => text.includes(n)).length;
    if (hits >= min) out.push({ rule: name, severity });
  }
  return out;
}

export function maxSeverity(ms) {
  for (const s of SEV_ORDER) if (ms.some((m) => m.severity === s)) return s;
  return "info";
}

export function info(buf, target) {
  return {
    tool: "yararun",
    version: TOOL_VERSION,
    target,
    size: buf.length,
    filetype: filetype(buf),
    entropy: entropy(buf),
    md5: createHash("md5").update(buf).digest("hex"),
    sha1: createHash("sha1").update(buf).digest("hex"),
    sha256: createHash("sha256").update(buf).digest("hex"),
  };
}

export function scan(buf, target) {
  const ms = scanRules(buf);
  return { ...info(buf, target), matches: ms, match_count: ms.length, max_severity: maxSeverity(ms) };
}

function cli(args) {
  const [cmd, path] = args;
  if (!cmd || !path || (cmd !== "info" && cmd !== "scan")) {
    stderr.write("usage: node index.js <info|scan> <file>\n");
    return 2;
  }
  let buf;
  try {
    buf = readFileSync(path);
  } catch (e) {
    stderr.write(`error: cannot read ${path}: ${e.message}\n`);
    return 2;
  }
  const res = cmd === "scan" ? scan(buf, path) : info(buf, path);
  console.log(JSON.stringify(res, null, 2));
  return cmd === "scan" && res.match_count > 0 ? 1 : 0;
}

// Run as a CLI only when invoked directly (robust on Windows + POSIX).
const isMain = (() => {
  try {
    return argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(argv[1]);
  } catch {
    return false;
  }
})();
if (isMain) {
  exit(cli(argv.slice(2)));
}
