/*
 * Custom YARARUN ruleset: hardcoded-secret / risky-config hunting for a
 * source tree, emitted as SARIF for GitHub code-scanning.
 *
 * These are STRUCTURAL patterns (prefixes / key names), not real credentials.
 * Tune to your org before gating CI on them.
 */

rule AWS_Access_Key_Id : secret credential {
    meta:
        severity = "critical"
        description = "Hardcoded AWS access key id (AKIA/ASIA prefix)"
    strings:
        $akia = /A(KIA|SIA)[0-9A-Z]{16}/ fullword
    condition:
        $akia
}

rule Private_Key_Block : secret credential {
    meta:
        severity = "critical"
        description = "PEM private key block committed to source"
    strings:
        $pem = "-----BEGIN"
        $key = "PRIVATE KEY-----"
    condition:
        $pem and $key
}

rule Generic_Api_Secret : secret {
    meta:
        severity = "high"
        description = "Generic api_key / secret assignment with a long value"
    strings:
        $a = /(api[_-]?key|secret|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/ nocase
    condition:
        $a
}

rule Debug_Backdoor_Flag : misconfig {
    meta:
        severity = "medium"
        description = "Debug/insecure flag left enabled in config"
    strings:
        $d1 = "DEBUG = True"
        $d2 = "verify=False" nocase
        $d3 = "ALLOWED_HOSTS = ['*']"
    condition:
        any of them
}
