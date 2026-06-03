/*
  soc-filedrop-content.yar — FILE-CONTENT ruleset for the risk-engine /analyze-file
  endpoint (Phase 9.2). A collector base64-encodes a dropped file and POSTs it; the
  engine YARA-scans the raw BYTES (compute_behavior_bytes) — so these rules match a
  binary PE as well as a text script. No `pe`/`math` modules (the engine compiles a
  shared, module-free ruleset): PE detection uses the raw MZ magic + ASCII import
  names, which is enough to categorize a dropper without parsing the PE structure.

  These also live in the SHARED ruleset, so they are tried on command-line buffers
  too — but `$mz at 0` only matches real file bytes, so they never fire on a command
  line. Scores are PRUDENT because /analyze-file verdicts can drive auto actions:
    >=90 escalate | >=70 contained | >=50 auto_promote | >=40 reviewed | <40 none
  A clean signed PE with no suspicious imports scores 0 -> verdict auto_closed.
*/

rule FileContent_PE_With_Injection_Imports
{
    meta:
        score = 70
        severity = "high"
        technique = "T1055"
    strings:
        $mz = { 4D 5A }
        $i1 = "VirtualAllocEx" nocase
        $i2 = "WriteProcessMemory" nocase
        $i3 = "CreateRemoteThread" nocase
        $i4 = "NtUnmapViewOfSection" nocase
        $i5 = "SetThreadContext" nocase
        $i6 = "QueueUserAPC" nocase
        $i7 = "RtlMoveMemory" nocase
    condition:
        $mz at 0 and 2 of ($i*)
}

rule FileContent_PE_Suspicious_Capabilities
{
    meta:
        score = 55
        severity = "medium"
        technique = "T1105"
    strings:
        $mz = { 4D 5A }
        $u1 = "URLDownloadToFile" nocase
        $u2 = "WinHttpOpenRequest" nocase
        $u3 = "InternetOpenUrl" nocase
        $s1 = "ShellExecute" nocase
        $s2 = "WinExec" nocase
        $s3 = "CreateProcess" nocase
        $r1 = "RegSetValueEx" nocase
        $r2 = "CurrentVersion\\Run" nocase
    condition:
        $mz at 0 and 2 of them
}

rule FileContent_Embedded_Script_Dropper
{
    meta:
        score = 60
        severity = "high"
        technique = "T1059.001"
    strings:
        $a = "FromBase64String" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "DownloadString" nocase
        $e = "DownloadFile" nocase
        $f = "-encodedcommand" nocase
        $g = "[Reflection.Assembly]::Load" nocase
        $h = "VirtualAlloc" nocase
    condition:
        3 of them
}

rule FileContent_Script_Obfuscation_Heavy
{
    meta:
        score = 50
        severity = "medium"
        technique = "T1027"
    strings:
        $c1 = "-join" nocase
        $c2 = "[char]" nocase
        $c3 = "[convert]::" nocase
        $c4 = "-bxor" nocase
        $c5 = "${"
        $c6 = "'+'"
        $c7 = "Invoke-Obfuscation" nocase
    condition:
        4 of them
}
