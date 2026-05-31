/*
  soc-powershell-behavior.yar — curated, self-contained YARA ruleset for
  command-line / decoded-script behavioral analysis (risk-engine in-process).
  Text-only (no pe/math modules, no external variables) so it compiles and
  matches against a plain string buffer (command_line + decoded payload).
  Inspired by public offensive-PowerShell indicators (Empire/PowerSploit).
*/

rule PS_Suspicious_Flags
{
    meta:
        score = 40
        severity = "medium"
        technique = "T1059.001"
    strings:
        $a = "-w hidden" nocase
        $b = "-windowstyle hidden" nocase
        $c = "-nop " nocase
        $d = "-noprofile" nocase
        $e = "-executionpolicy bypass" nocase
        $f = "-ep bypass" nocase
    condition:
        2 of them
}

rule PS_IEX_Exec
{
    meta:
        score = 70
        severity = "high"
        technique = "T1059.001"
    strings:
        $a = "IEX" nocase
        $b = "Invoke-Expression" nocase
        $c = "scriptblock]::create(" nocase
    condition:
        any of them
}

rule PS_Download_Cradle
{
    meta:
        score = 75
        severity = "high"
        technique = "T1105"
    strings:
        $a = "DownloadString" nocase
        $b = "DownloadFile" nocase
        $c = "DownloadData" nocase
        $d = "Net.WebClient" nocase
        $e = "Invoke-WebRequest" nocase
        $f = "Start-BitsTransfer" nocase
        $g = "System.Net.Http" nocase
    condition:
        any of them
}

rule PS_AMSI_Bypass
{
    meta:
        score = 90
        severity = "critical"
        technique = "T1562.001"
    strings:
        $a = "amsiInitFailed" nocase
        $b = "AmsiUtils" nocase
        $c = "amsiContext" nocase
        $d = "System.Management.Automation.AmsiUtils" nocase
    condition:
        any of them
}

rule PS_Reflection_Inject
{
    meta:
        score = 85
        severity = "high"
        technique = "T1055"
    strings:
        $a = "Reflection.Assembly" nocase
        $b = "VirtualAlloc" nocase
        $c = "[DllImport" nocase
        $d = "kernel32" nocase
        $e = "CreateThread" nocase
    condition:
        2 of them
}

rule Cred_Dumping_Tooling
{
    meta:
        score = 95
        severity = "critical"
        technique = "T1003"
    strings:
        $a = "Invoke-Mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsadump" nocase
        $d = "mimikatz" nocase
        $e = "Out-Minidump" nocase
        $f = "comsvcs.dll" nocase
    condition:
        any of them
}
