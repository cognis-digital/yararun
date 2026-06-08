/*
 * YARARUN example ruleset (defensive triage).
 * These rules match benign indicator strings for demonstration only.
 */

rule SuspiciousPowerShell {
    meta:
        description = "PowerShell download+encodedcommand pattern"
        severity = "high"
    strings:
        $enc = "-EncodedCommand" nocase
        $dl  = /(DownloadString|Invoke-WebRequest)/ nocase
        $hide = "-WindowStyle Hidden" nocase
    condition:
        $enc and ($dl or $hide)
}

rule EvalRegex {
    meta:
        description = "obfuscated eval/iex invocation"
        severity = "medium"
    strings:
        $a = /iex\s*\(/ nocase
    condition:
        $a
}

rule MZMagic {
    meta:
        description = "embedded PE/MZ header bytes"
        severity = "low"
    strings:
        $mz = { 4d 5a 90 00 }
    condition:
        $mz
}
