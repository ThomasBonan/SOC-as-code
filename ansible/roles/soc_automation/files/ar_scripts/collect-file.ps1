<#
  collect-file.ps1 — Wazuh Active Response collector (Windows endpoint, Phase 9.2)
  ════════════════════════════════════════════════════════════════════════════════
  Lit le fichier qu'un event Sysmon EID11 (FileCreate) signale comme déposé,
  calcule son SHA256, en base64 un EXTRAIT borné, et ré-injecte une ligne JSON dans
  un log surveillé par l'agent Wazuh. Le manager décode cet event -> règle
  soc_filedrop_content -> webhook dédié -> Shuffle POST /analyze-file (YARA contenu).

  POURQUOI un EXTRAIT borné : un event Wazuh est plafonné (~64KB analysisd). On ne
  peut pas faire transiter 1 Mo de base64. On cape donc à MaxBytes (déf. 24576 =
  24KB brut -> ~32KB base64) : suffisant pour catégoriser (en-tête MZ/PE + table
  d'imports proche du début + corps des scripts). Le moteur /analyze-file marque
  `truncated:true`. Pour une analyse plein-fichier, voir la doc (POST direct ou
  partage de fichier) — hors périmètre de ce collecteur Wazuh-natif.

  CONVENTION WAZUH ACTIVE RESPONSE (v4)
  -------------------------------------
  L'alerte arrive en JSON sur STDIN :
    {"version":1,"command":"add","parameters":{"alert":{...},"program":"..."}}
  command = "add" (déclenchement) | "delete" (cleanup — NOOP ici, lecture seule).

  GARDE-FOUS (ordre, premier match = NOOP) :
    1. SOC_FC_DRY_RUN=1            -> log "would-collect", aucune lecture
    2. chemin dans whitelist       -> skip (faux positifs connus, ex. dossiers MAJ)
    3. extension hors allowlist    -> skip (on ne lit que exe/dll/ps1/...)
    4. fichier absent / locké       -> log "unavailable" (TOCTOU : dropper auto-suppr.)
    5. taille > HardMaxBytes        -> on lit quand même MaxBytes (extrait), flag tronqué

  DESTRUCTIVITÉ : AUCUNE. Lecture seule + écriture du log de collecte. Ne modifie
  jamais le fichier suspect ni le système.

  INSTALLATION (hors repo K8s — flotte Windows, via GPO/SCCM/manuel) : voir
  ansible/roles/soc_automation/files/ar_scripts/README-collect-file.md
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ── Configuration (sidecar, overridable sans toucher au script) ─────────────────
$ConfPath  = Join-Path $PSScriptRoot 'collect-file.conf'
$Cfg = @{
    LogPath      = 'C:\ProgramData\soc\filedrop-collect.log'
    MaxBytes     = 24576       # extrait base64é (cap event Wazuh)
    DryRun       = $false
    AllowExt     = @('.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.jse','.hta','.wsf','.com','.sys')
    WhitelistRe  = @()         # regex de chemins à ignorer (faux positifs)
    OwnLogDir    = 'C:\ProgramData\soc'
}
if (Test-Path $ConfPath) {
    foreach ($line in Get-Content $ConfPath -ErrorAction SilentlyContinue) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $k,$v = $line -split '=',2
        $k = $k.Trim(); $v = $v.Trim()
        switch ($k) {
            'SOC_FC_DRY_RUN'  { $Cfg.DryRun   = ($v -eq '1' -or $v -ieq 'true') }
            'SOC_FC_MAXBYTES' { if ($v -match '^\d+$') { $Cfg.MaxBytes = [int]$v } }
            'SOC_FC_LOGPATH'  { if ($v) { $Cfg.LogPath = $v } }
            'SOC_FC_ALLOWEXT' { if ($v) { $Cfg.AllowExt = ($v -split ',' | ForEach-Object { $_.Trim().ToLower() }) } }
            'SOC_FC_WHITELIST'{ if ($v) { $Cfg.WhitelistRe = ($v -split ';' | Where-Object { $_ }) } }
        }
    }
}

function Write-CollectLine([hashtable]$obj) {
    # Une ligne JSON compacte (sans retour) dans le log surveillé par l'agent.
    try { New-Item -ItemType Directory -Force -Path (Split-Path $Cfg.LogPath) | Out-Null } catch {}
    $json = ($obj | ConvertTo-Json -Compress -Depth 4)
    # garde-fou : jamais de retour ligne dans la valeur (un event = une ligne)
    $json = $json -replace "`r"," " -replace "`n"," "
    Add-Content -Path $Cfg.LogPath -Value $json -Encoding utf8
}

# ── Lire l'alerte AR sur stdin ──────────────────────────────────────────────────
$raw = [Console]::In.ReadToEnd()
if (-not $raw) { exit 0 }
try { $ar = $raw | ConvertFrom-Json } catch { exit 0 }

$command = $ar.command
if ($command -eq 'delete') { exit 0 }   # cleanup : lecture seule, rien à défaire

$alert    = $ar.parameters.alert
$agentName = $null; if ($alert.agent) { $agentName = $alert.agent.name }
$ruleId    = $null; if ($alert.rule)  { $ruleId   = $alert.rule.id }

# TargetFilename (EID11) ; fallback Image (au cas où routé sur un EID1)
$ed = $alert.data.win.eventdata
$filePath = $null
if ($ed) {
    if ($ed.targetFilename) { $filePath = $ed.targetFilename }
    elseif ($ed.TargetFilename) { $filePath = $ed.TargetFilename }
    elseif ($ed.image)      { $filePath = $ed.image }
    elseif ($ed.Image)      { $filePath = $ed.Image }
}
if (-not $filePath) { exit 0 }   # rien à collecter

$base = @{
    soc_filedrop = '1'
    file_path    = $filePath
    agent        = $agentName
    rule_id      = $ruleId
    collector    = 'collect-file.ps1'
}

# ── Garde-fou 1 : dry-run ───────────────────────────────────────────────────────
if ($Cfg.DryRun) {
    Write-CollectLine ($base + @{ soc_status='would-collect'; note='dry-run' })
    exit 0
}

# ── Garde-fou 2 : whitelist de chemins (faux positifs) ──────────────────────────
foreach ($re in $Cfg.WhitelistRe) {
    if ($filePath -match $re) {
        Write-CollectLine ($base + @{ soc_status='skipped-whitelist'; matched=$re })
        exit 0
    }
}
# Ne jamais lire notre propre log de collecte (anti-boucle)
if ($filePath -like "$($Cfg.OwnLogDir)*") { exit 0 }

# ── Garde-fou 3 : allowlist d'extensions ────────────────────────────────────────
$ext = [System.IO.Path]::GetExtension($filePath).ToLower()
if ($Cfg.AllowExt -and ($Cfg.AllowExt -notcontains $ext)) {
    Write-CollectLine ($base + @{ soc_status='skipped-ext'; ext=$ext })
    exit 0
}

# ── Garde-fou 4 : fichier présent/lisible (TOCTOU) ──────────────────────────────
if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
    Write-CollectLine ($base + @{ soc_status='unavailable'; note='file gone (TOCTOU)' })
    exit 0
}

try {
    $fi   = Get-Item -LiteralPath $filePath -ErrorAction Stop
    $size = $fi.Length
    $sha  = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()

    # Lecture bornée (extrait) — flux ouvert en lecture partagée pour éviter les locks.
    $cap  = [int]$Cfg.MaxBytes
    $fs   = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Open,
                                   [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $toRead = [Math]::Min([int64]$cap, $size)
        $buf = New-Object byte[] $toRead
        $read = $fs.Read($buf, 0, $toRead)
        if ($read -lt $toRead) { $buf = $buf[0..([Math]::Max($read-1,0))] }
    } finally { $fs.Dispose() }

    $b64 = [System.Convert]::ToBase64String($buf)
    Write-CollectLine ($base + @{
        soc_status  = 'collected'
        sha256      = $sha
        size        = $size
        truncated   = ([int64]$size -gt [int64]$cap)
        content_b64 = $b64
    })
}
catch {
    Write-CollectLine ($base + @{ soc_status='error'; note=("{0}" -f $_.Exception.Message) })
}
exit 0
