/*
 * Custom triage ruleset for the 02-deep demo.
 * Exercises the harder engine features:
 *   hex strings with wildcards/jumps, regex strings, #count comparisons,
 *   offset anchoring, N-of set conditions, the `xor` modifier, the
 *   `entropy` / `filetype` module variables, and uint*() integer functions.
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
        description = "MZ..PE header with wildcarded DOS stub and jump, MZ at 0"
    strings:
        // 'MZ' then any 2 bytes, a 4..64 byte jump, then 'PE\0\0'
        $stub = { 4D 5A ?? ?? [4-64] 50 45 00 00 }
    condition:
        $stub and uint16(0) == 0x5A4D
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

rule XOR_Hidden_Executable : evasion encoded {
    meta:
        severity = "critical"
        description = "Single-byte XOR-encoded MZ/DOS-stub hidden in the blob"
    strings:
        $mz   = "MZ" xor(0x01-0xff)
        $stub = "This program cannot be run in DOS mode" xor(0x01-0xff)
    condition:
        // require the encoded copy, not the plaintext header at offset 0
        #stub >= 1 and #mz >= 1
}

rule Packed_Payload_Entropy : packer {
    meta:
        severity = "medium"
        description = "High-entropy region typical of packed/encrypted payloads"
    condition:
        entropy >= 7.5 and filetype == "pe" and filesize > 1KB
}
