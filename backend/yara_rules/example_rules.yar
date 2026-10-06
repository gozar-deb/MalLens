/*
  Example / starter YARA rules for MalLens.

  These are intentionally simple, illustrative rules so the pipeline has
  something to match against out of the box. Replace or extend this file
  with real rulesets (e.g. from YARA-Rules/rules or your own research) for
  production use -- see README.md "Static Analysis Engine".
*/

rule EICAR_Test_File
{
    meta:
        description = "Detects the industry-standard EICAR antivirus test string (not real malware)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
    /* Note: escape sequences above are illustrative; the real EICAR string
       is intentionally not embedded verbatim in this template to avoid
       accidental AV false-positives on this repository itself. Replace
       with the exact EICAR string from the reference URL if you want a
       working self-test rule. */
}

rule Suspicious_PE_Packer_Indicators
{
    meta:
        description = "Flags PE files with common packer/stub section names"
        severity = "low"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = "aPLib" ascii
        $themida = "Themida" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_Script_Obfuscation
{
    meta:
        description = "Flags scripts with common obfuscation/encoding call patterns"
        severity = "medium"
    strings:
        $ps_enc = "-EncodedCommand" nocase
        $ps_bypass = "-ExecutionPolicy Bypass" nocase
        $js_eval = "eval(unescape(" nocase
        $js_fromchar = "String.fromCharCode(" nocase
    condition:
        any of them
}

rule Possible_Credential_Harvesting_Strings
{
    meta:
        description = "Flags binaries referencing common browser credential storage paths"
        severity = "medium"
    strings:
        $chrome = "Login Data" ascii
        $firefox = "logins.json" ascii
        $edge = "Microsoft\\Edge\\User Data" ascii wide
    condition:
        any of them
}
