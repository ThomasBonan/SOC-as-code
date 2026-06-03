# collect-file.ps1 — collecteur de contenu (Phase 9.2)

Collecteur Active Response Wazuh qui **lit un fichier déposé** (signalé par un event
Sysmon EID11 FileCreate), calcule son SHA256, en base64 un **extrait borné**, et
**ré-injecte** une ligne JSON dans un log surveillé par l'agent. Le manager classe
cet event (`soc_filedrop_content`) → webhook dédié → Shuffle `POST /analyze-file`
(YARA sur le contenu réel, cf. `risk-engine-app.py` `compute_behavior_bytes`).

> **Périmètre.** Ce repo gère le **stack SOC K8s + le pod manager Wazuh**, PAS la
> flotte Windows. Wazuh ne distribue **pas** les binaires AR aux agents : le script
> ci-dessous doit être **installé sur chaque endpoint** (GPO / SCCM / Intune /
> manuel). Le manager fournit le déclencheur AR, le décodeur, la règle et le routage.

## Voie SANS script (recommandée) : Wazuh FIM

Si tu ne veux **aucun binaire sur les agents**, utilise **Wazuh FIM (syscheck)**,
configurable par l'**`agent.conf` centralisé** (distribué par le manager — config
seule). Un fichier exécutable/script **ajouté** dans un dossier sensible déclenche
la rule `100274` (basée sur la 554 native) qui porte `syscheck.sha256_after` :

```xml
<!-- agent.conf du groupe (ex. default) — poussé par le manager, 0 binaire -->
<syscheck>
  <disabled>no</disabled>
  <alert_new_files>yes</alert_new_files>            <!-- requis : alerter les ajouts -->
  <directories realtime="yes" check_all="yes" report_changes="yes"
    >C:\Windows\Temp,C:\ProgramData,C:\Users\Public,C:\Users\*\AppData\Local\Temp</directories>
  <!-- C:\Windows\System32 possible mais TRÈS bruyant en realtime — à éviter large -->
</syscheck>
```

- **Hash** : `syscheck.sha256_after` → `/normalize` (déjà adapté) → Cortex/MISP via
  wf-filedrop. Catégorise tout malware **connu**, sans lire le fichier.
- **Contenu texte** : `report_changes="yes"` → diff des scripts (.ps1/.bat).
- **Limite** : pas de contenu **binaire** (PE) — un zero-day compilé inconnu des feeds
  ne sera pas catégorisé par contenu (seul le collecteur ci-dessous le permet).
- **Coût** : `realtime` sur des dossiers larges est lourd → scoper aux dossiers à risque.

Déploiement : pousser ce bloc dans `/var/ossec/etc/shared/<groupe>/agent.conf` du
manager (les agents du groupe le récupèrent). La règle `100274` + le routage
`soc_filedrop_content → wf-filedrop` sont déjà fournis par le repo.

Le **collecteur ci-dessous reste une option avancée opt-in** pour obtenir le contenu
**binaire** complet (analyse PE par /analyze-file), au prix d'un script sur les agents.

## Chaîne complète

```
Sysmon EID11 (FileCreate, exe déposé)
   │  rule Wazuh EID11 (group sysmon_eid11_detections)
   ▼
<active-response> collect-file (location=local)         ← déclencheur (manager ossec.conf)
   │  l'agent exécute collect-file.ps1
   ▼
lit TargetFilename, SHA256 + base64(extrait ≤ MaxBytes)
   │  écrit 1 ligne JSON
   ▼
C:\ProgramData\soc\filedrop-collect.log                 ← <localfile> (agent.conf partagé)
   │  agent → manager
   ▼
décodeur json + rule soc_filedrop_content (level 10)    ← manager (in-pod, éphémère)
   │  <integration> group soc_filedrop_content
   ▼
webhook Shuffle wf-filedrop → POST /analyze-file        ← Phase B
   │  verdict (auto_closed / reviewed / auto_promoted / contained / escalated)
   ▼
TheHive : tags category/verdict/mitre (Phase E)
```

## Contrainte de taille (importante)

Un event Wazuh est plafonné (~64 KB, `analysisd OS_MAXSTR`). On **ne peut pas** faire
transiter 1 Mo de base64. Le collecteur cape à `MaxBytes` (défaut **24576** = 24 KB
brut → ~32 KB base64). Suffisant pour **catégoriser** :
- PE : en-tête `MZ`/`PE` + table d'imports souvent proche du début + chaînes ;
- scripts : le corps malveillant tient quasi toujours dans 24 KB.

Le moteur renvoie `truncated:true`. Pour une analyse **plein-fichier**, deux options
hors-Wazuh (non fournies, à évaluer selon ta posture réseau/sécurité) :
1. **POST direct** endpoint → `https://risk-engine.apps.soc.lab/analyze-file` (expose
   l'endpoint à la flotte + nécessite une clé API — surface d'attaque accrue) ;
2. **Partage/objet** : déposer le fichier sur un share, Shuffle le récupère.

## Installation sur l'endpoint Windows

1. **Sysmon** : EID11 FileCreate doit être loggé pour les répertoires sensibles
   (`C:\Windows\`, `\Temp\`, profils). Exemple de règle Sysmon :
   ```xml
   <FileCreate onmatch="include">
     <TargetFilename condition="end with">.exe</TargetFilename>
     <TargetFilename condition="end with">.dll</TargetFilename>
     <TargetFilename condition="contains">\Windows\</TargetFilename>
   </FileCreate>
   ```
2. **Binaire AR** : copier `collect-file.ps1` dans
   `C:\Program Files (x86)\ossec-agent\active-response\bin\collect-file.ps1`.
   Wazuh invoque les `.ps1` AR via `powershell.exe`. Si ta version exige un wrapper,
   ajouter `collect-file.cmd` :
   ```bat
   @echo off
   PowerShell -ExecutionPolicy Bypass -NoProfile -File "%~dp0collect-file.ps1"
   ```
3. **Config (optionnel)** : `...\active-response\bin\collect-file.conf`
   ```
   SOC_FC_DRY_RUN=1            # 1 = log "would-collect" sans lire (recommandé au début)
   SOC_FC_MAXBYTES=24576
   SOC_FC_LOGPATH=C:\ProgramData\soc\filedrop-collect.log
   SOC_FC_ALLOWEXT=.exe,.dll,.scr,.ps1,.bat,.cmd,.vbs,.js,.hta
   SOC_FC_WHITELIST=\\\\Microsoft\\\\EdgeUpdate\\\\;\\\\Package Cache\\\\   # regex, séparés par ;
   ```
   **Démarrer en `DRY_RUN=1`** (pattern AR du SOC) : valider le volume/les faux
   positifs avant de basculer à `0`.

## Config côté manager (fournie par le repo)

- **Déclencheur AR** (ossec.conf manager) — déployé par `180-soc-automation`
  (`wazuh_filedrop_collector.yml`, gated `soc_automation_enable_filedrop_collector`) :
  ```xml
  <command>
    <name>soc-collect-file</name>
    <executable>collect-file.ps1</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <command>soc-collect-file</command>
    <location>local</location>
    <rules_group>sysmon_eid11_detections</rules_group>
  </active-response>
  ```
- **localfile** (agent.conf partagé — distribué aux agents par le manager) :
  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>C:\ProgramData\soc\filedrop-collect.log</location>
  </localfile>
  ```
- **Décodeur + règle** `soc_filedrop_rules.xml` : classe l'event ré-injecté
  (`data.soc_filedrop=1`) en `soc_filedrop_content` (level 10) — déployé in-pod.
- **Routage** : la règle `soc_filedrop_content` est routée vers le workflow
  `wf-filedrop` (Phase B) qui appelle `/analyze-file`.

## Garde-fous du script

| # | Condition | Effet |
|---|-----------|-------|
| 1 | `SOC_FC_DRY_RUN=1` | log `would-collect`, aucune lecture |
| 2 | chemin ∈ whitelist | `skipped-whitelist` |
| 3 | extension ∉ allowlist | `skipped-ext` |
| 4 | fichier absent/locké | `unavailable` (TOCTOU — droppers auto-suppr.) |
| 5 | taille > MaxBytes | lit l'extrait, `truncated:true` |

**Destructivité : aucune.** Lecture seule (FileShare ReadWrite, ne lock pas le
fichier) + écriture du log de collecte. Ne modifie jamais le fichier ni le système.

## Validation

- DRY_RUN : déclencher un drop atomic → vérifier les lignes `would-collect` dans le
  log de collecte côté endpoint, puis l'event `soc_filedrop_content` côté manager
  (`/var/ossec/logs/alerts/alerts.json`).
- LIVE : basculer `SOC_FC_DRY_RUN=0`, rejouer → vérifier `content_b64` présent et le
  verdict `/analyze-file` dans Shuffle/TheHive.
