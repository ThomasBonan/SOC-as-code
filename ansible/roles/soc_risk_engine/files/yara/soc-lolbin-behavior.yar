/*
  soc-lolbin-behavior.yar — command-line TTP ruleset (LOLBins, persistence,
  defense evasion, discovery) for the risk-engine in-process behavioral layer.
  Complements soc-powershell-behavior.yar (PowerShell obfuscation) and the
  MITRE-driven score (rule.mitre.id). Text-only (no pe/math modules, no external
  variables) so it compiles and matches against a plain string buffer
  (command_line + decoded payload). Scores are PRUDENT because most of these
  binaries are also used legitimately — single common LOLBins land in the
  reviewed band (<50), destructive/credential indicators escalate.

  Score bands (see group_vars soc_risk_behavior.floors):
    >=90 escalate | >=70 contained | >=50 auto_promote | >=40 reviewed | <40 none
*/

rule LOLBin_Scheduled_Task_Persistence
{
    meta:
        score = 45
        severity = "medium"
        technique = "T1053.005"
    strings:
        $a = "schtasks" nocase
        $b = "/create" nocase
        $c = "/sc " nocase
    condition:
        $a and ($b or $c)
}

rule LOLBin_RunKey_Persistence
{
    meta:
        score = 45
        severity = "medium"
        technique = "T1547.001"
    strings:
        $a = "reg " nocase
        $b = "add" nocase
        $c = "CurrentVersion\\Run" nocase
        $d = "CurrentVersion\\RunOnce" nocase
    condition:
        $a and $b and ($c or $d)
}

rule Discovery_Recon_Cluster
{
    meta:
        score = 40
        severity = "low"
        technique = "T1087"
    strings:
        $a = "whoami /all" nocase
        $b = "net group" nocase
        $c = "nltest" nocase
        $d = "net localgroup" nocase
        $e = "systeminfo" nocase
        $f = "net view" nocase
        $g = "dsquery" nocase
        $h = "quser" nocase
    condition:
        2 of them
}

rule Execution_WMIC_Process_Create
{
    meta:
        score = 55
        severity = "medium"
        technique = "T1047"
    strings:
        $a = "wmic" nocase
        $b = "process" nocase
        $c = "call" nocase
        $d = "create" nocase
    condition:
        all of them
}

rule LOLBin_Download_Cradle
{
    meta:
        score = 70
        severity = "high"
        technique = "T1105"
    strings:
        $cu = "certutil" nocase
        $url = "-urlcache" nocase
        $dec = "-decode" nocase
        $split = "-split" nocase
        $bits = "bitsadmin" nocase
        $tx = "/transfer" nocase
        $curl = "curl " nocase
        $http = "http" nocase
    condition:
        ($cu and ($url or $dec or $split)) or
        ($bits and $tx) or
        ($curl and $http and ($dec or $url))
}

rule LOLBin_Proxy_Execution
{
    meta:
        score = 75
        severity = "high"
        technique = "T1218"
    strings:
        $mshta = "mshta" nocase
        $js = "javascript:" nocase
        $vbs = "vbscript:" nocase
        $rundll = "rundll32" nocase
        $regsvr = "regsvr32" nocase
        $scrobj = "scrobj" nocase
        $ihttp = "/i:http" nocase
        $http = "http" nocase
    condition:
        ($mshta and ($js or $vbs or $http)) or
        ($rundll and $js) or
        ($regsvr and ($scrobj or $ihttp))
}

rule Account_Manipulation_Local
{
    meta:
        score = 70
        severity = "high"
        technique = "T1136.001"
    strings:
        $net = "net" nocase
        $user = "user" nocase
        $add = "/add" nocase
        $lg = "localgroup" nocase
        $admins = "administrators" nocase
    condition:
        $net and $add and ($user or ($lg and $admins))
}

rule PrivEsc_UAC_Bypass_Common
{
    meta:
        score = 75
        severity = "high"
        technique = "T1548.002"
    strings:
        $fod = "fodhelper" nocase
        $cd = "computerdefaults" nocase
        $mss = "ms-settings" nocase
        $del = "DelegateExecute" nocase
        $ev = "eventvwr" nocase
        $sdc = "sdclt" nocase
    condition:
        $fod or $cd or $sdc or ($mss and $del) or $ev
}

rule Defense_Evasion_EventLog_Clear
{
    meta:
        score = 80
        severity = "high"
        technique = "T1070.001"
    strings:
        $we = "wevtutil" nocase
        $cl = "cl " nocase
        $clr = "clear-log" nocase
        $cle = "Clear-EventLog" nocase
    condition:
        ($we and ($cl or $clr)) or $cle
}

rule Defense_Evasion_Disable_Defender
{
    meta:
        score = 90
        severity = "critical"
        technique = "T1562.001"
    strings:
        $mp = "Set-MpPreference" nocase
        $rt = "DisableRealtimeMonitoring" nocase
        $add = "Add-MpPreference" nocase
        $excl = "ExclusionPath" nocase
        $wd = "WinDefend" nocase
        $scs = "sc stop" nocase
        $scd = "sc config" nocase
        $nf = "netsh advfirewall set" nocase
        $off = "state off" nocase
    condition:
        ($mp and $rt) or ($add and $excl) or
        (($scs or $scd) and $wd) or ($nf and $off)
}

rule Defense_Evasion_ShadowCopy_Delete
{
    meta:
        score = 90
        severity = "critical"
        technique = "T1490"
    strings:
        $vss = "vssadmin" nocase
        $del = "delete" nocase
        $sh = "shadows" nocase
        $wmic = "wmic" nocase
        $scc = "shadowcopy" nocase
        $bcd = "bcdedit" nocase
        $rec = "recoveryenabled" nocase
        $bsp = "bootstatuspolicy" nocase
        $wb = "wbadmin" nocase
        $cat = "catalog" nocase
    condition:
        ($vss and $del and $sh) or
        ($wmic and $scc and $del) or
        ($bcd and ($rec or $bsp)) or
        ($wb and $del and $cat)
}

rule Credential_Access_Registry_Hive_Dump
{
    meta:
        score = 90
        severity = "critical"
        technique = "T1003.002"
    strings:
        $reg = "reg " nocase
        $save = "save" nocase
        $sam = "hklm\\sam" nocase
        $sys = "hklm\\system" nocase
        $sec = "hklm\\security" nocase
    condition:
        $reg and $save and ($sam or $sys or $sec)
}

rule Credential_Access_LSASS_Dump
{
    meta:
        score = 95
        severity = "critical"
        technique = "T1003.001"
    strings:
        $lsass = "lsass" nocase
        $comsvcs = "comsvcs.dll" nocase
        $minidump = "MiniDump" nocase
        $procdump = "procdump" nocase
        $rundll = "rundll32" nocase
    condition:
        ($comsvcs and $minidump) or
        ($rundll and $comsvcs and $lsass) or
        ($procdump and $lsass)
}
