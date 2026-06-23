// Smoke tests for the JS port. Run: node --test  (Node >= 18, std-only).
import { test } from "node:test";
import assert from "node:assert/strict";
import { entropy, filetype, scanRules, maxSeverity, info, scan } from "./index.js";

test("entropy bounds", () => {
  assert.equal(entropy(Buffer.from([])), 0.0);
  assert.equal(entropy(Buffer.from("AAAA")), 0.0);
  const all = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.ok(Math.abs(entropy(all) - 8.0) < 1e-3);
});

test("filetype magic", () => {
  assert.equal(filetype(Buffer.from("MZ\x90\x00", "latin1")), "pe");
  assert.equal(filetype(Buffer.from("\x7fELFxxxx", "latin1")), "elf");
  assert.equal(filetype(Buffer.from("%PDF-1.7")), "pdf");
  assert.equal(filetype(Buffer.from("plain ascii text")), "text");
  assert.equal(filetype(Buffer.from([0, 1, 2, 200, 255])), "data");
});

test("scan ransom critical", () => {
  const note = Buffer.from(
    "your files have been encrypted, send bitcoin to our BTC wallet to decrypt"
  );
  const ms = scanRules(note);
  assert.ok(ms.some((m) => m.rule === "Ransom_Note" && m.severity === "critical"));
  assert.equal(maxSeverity(ms), "critical");
});

test("scan powershell", () => {
  const ms = scanRules(Buffer.from("powershell -enc IEX DownloadString FromBase64String"));
  assert.ok(ms.some((m) => m.rule === "Embedded_PowerShell"));
});

test("scan clean", () => {
  assert.equal(scanRules(Buffer.from("just ordinary text")).length, 0);
});

test("scan eicar", () => {
  const eicar = Buffer.from(
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  );
  assert.ok(scanRules(eicar).some((m) => m.rule === "EICAR_Test_File"));
});

test("info known sha256 vector", () => {
  const i = info(Buffer.from("abc"), "x");
  assert.equal(i.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(i.md5, "900150983cd24fb0d6963f7d28e17f72");
});

test("scan result shape", () => {
  const r = scan(Buffer.from("powershell -enc IEX DownloadString FromBase64String"), "t");
  assert.equal(r.tool, "yararun");
  assert.ok(r.match_count >= 1);
  assert.equal(typeof r.sha256, "string");
});
