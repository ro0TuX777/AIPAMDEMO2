/*
 * AIPAM built-in starter YARA rules for first-class binary analysis.
 * These are intentionally broad triage indicators, not high-fidelity
 * detections. Drop additional .yar/.yara files in this directory to extend.
 */

rule AIPAM_PE_Executable
{
    meta:
        description = "Windows PE executable (MZ/PE header)"
        category = "file_format"
        severity = "info"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule AIPAM_ELF_Executable
{
    meta:
        description = "ELF executable / shared object"
        category = "file_format"
        severity = "info"
    condition:
        uint32(0) == 0x464C457F
}

rule AIPAM_Suspicious_PowerShell
{
    meta:
        description = "Encoded or download-cradle PowerShell content"
        category = "suspicious"
        severity = "high"
    strings:
        $enc = "-enc" nocase
        $ec = "-encodedcommand" nocase
        $b64 = "FromBase64String" nocase
        $dl = "DownloadString" nocase
        $iex = "IEX" nocase
    condition:
        2 of them
}

rule AIPAM_Embedded_URL
{
    meta:
        description = "Embedded HTTP/HTTPS URL"
        category = "indicator"
        severity = "low"
    strings:
        $http = "http://" nocase
        $https = "https://" nocase
    condition:
        any of them
}

rule AIPAM_UPX_Packed
{
    meta:
        description = "UPX packer signature present"
        category = "packer"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upxbang = "UPX!"
    condition:
        2 of them
}
