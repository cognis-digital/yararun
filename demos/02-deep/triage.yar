/*
 * Custom triage ruleset for the 02-deep demo.
 * Demonstrates hex strings with wildcards/jumps, regex strings,
 * #count comparisons, anchoring, and N-of set conditions.
 */

rule Dropper_PowerShell_Chain : apt script {
    meta:
        author = "yararun"
        severity = "high"
        description = "Encoded PowerShell download-cradle (multi-indicator)"
    strings:
        $ps   = "powershell" nocase
        $enc  = "-enc" nocase
        $dl   = "DownloadString" nocase
        $b64  = "FromBase64String" nocase
        $iex  = "IEX" fullword
    condition:
        $ps and 3 of ($enc, $dl, $b64, $iex)
}

rule Embedded_PE_via_HexHeader : pe embedded {
    meta:
        severity = "medium"
        description = "MZ..PE header with wildcarded DOS stub and jump"
    strings:
        // 'MZ' then any 2 bytes, a 4..8 byte jump, then 'PE\0\0'
        $stub = { 4D 5A ?? ?? [4-64] 50 45 00 00 }
    condition:
        $stub
}

rule C2_Beacon_URL : network ioc {
    meta:
        severity = "high"
        description = "Multiple hardcoded C2 URLs and a Tor onion fallback"
    strings:
        $url   = /https?:\/\/[a-z0-9.\-]{4,}\/[a-z0-9\/_.\-]*/ nocase
        $onion = /[a-z2-7]{16}\.onion/ nocase
    condition:
        $onion and #url >= 2
}
