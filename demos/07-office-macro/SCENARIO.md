# Demo 07 — Malicious Office macro (auto-exec downloader)

## Context (defensive / authorized triage)

A finance user reported a suspicious `invoice_2026.xlsm`. The mail-security
team detonated it in a sandbox and pulled the VBA project with `olevba`. They
want to confirm the auto-exec + shell pattern programmatically and feed the
verdict into their ticketing pipeline.

`invoice_macro.vba` carries the textbook combination: an `Auto_Open` /
`Document_Open` entry point, `CreateObject("WScript.Shell")`, and a `.Run`
to a PowerShell downloader. The encoded command body has been removed.

## Run it

```
python -m yararun scan demos/07-office-macro/invoice_macro.vba
python -m yararun --format json scan demos/07-office-macro/invoice_macro.vba
```

## Expected

- `VBScript_Macro` fires (severity **high**): an auto-exec entry point + a
  `CreateObject` + a `.Run`/`WScript.Shell`.
- `Embedded_PowerShell` may also fire on the `powershell -enc` cradle.
- Exit code `1`.

## How to act

Quarantine the original attachment, pivot on the sender and any other
recipients of the same file, extract and decode the PowerShell stage for the
real C2/dropper URL, and add the macro's distinctive strings to your mail
gateway and EDR block lists.
