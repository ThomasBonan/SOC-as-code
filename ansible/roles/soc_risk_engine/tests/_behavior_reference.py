# Standalone copy of the NEW risk-engine logic for local validation.
# Mirrors exactly what will go into risk-engine-app.py.j2 (no Jinja here).
import base64
import json
import os
import re

# ── Behavioral floors (configurable via group_vars → rendered constants) ──────
# Maps a behavioral severity score (0-100, from YARA/decode/MITRE) to a MINIMUM
# final risk score. The engine takes max(weighted_scenario_score, floor):
# behavior can only RAISE the score, never lower it → tuned scores stay intact.
BEHAVIOR_FLOORS = [
    (90, 90),   # critical (AMSI bypass, cred dumping, impact)   → escalate
    (70, 75),   # high (download cradle, IEX remote, inject)     → contained
    (50, 50),   # medium (encoded command present, persistence)  → auto_promoted
    (40, 20),   # low-confidence TTP (recon, single LOLBin)       → reviewed
]                # NB: < 40 stays below → no floor, surfaced in tags only.
# Base score for "an encoded/obfuscated command is present" even when the
# decoded content matches no malicious rule (obfuscation = weak signal).
ENCODED_PRESENT_SCORE = 50

YARA_RULES_PATH = "/config/yara"
# MITRE map: point at the source-of-truth JSON for local tests (overridable).
MITRE_SEVERITY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "files", "mitre-severity.json")

_ENC_RE = re.compile(r"-e(?:nc|ncodedcommand|ncoded)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_SHA256_RE = re.compile(r"SHA256=([A-Fa-f0-9]{64})")
_URL_RE = re.compile(r"https?://[^\s'\"<>|]+", re.I)
# Universal artifact extraction (Phase 10 / normalize v2).
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_IP_SKIP = ("127.", "0.0.0.0", "::1", "255.255.255.255")


def _clean_ip(v):
    if not isinstance(v, str):
        return ""
    s = v.strip()
    if not s or s.startswith("$") or not _IPV4_RE.match(s):
        return ""
    if any(s == p or s.startswith(p) for p in _IP_SKIP):
        return ""
    return s


def _clean_domain(v):
    if not isinstance(v, str):
        return ""
    s = v.strip().rstrip(".").lower()
    if not s or s.startswith("$") or _IPV4_RE.match(s):
        return ""
    return s if _DOMAIN_RE.match(s) else ""

# yara compiled handle (lazy, cached). None if yara unavailable or no rules.
_YARA = None
_YARA_TRIED = False

_MITRE_DEFAULT = {
    "version": "baked",
    "default": 40,
    "tactics": {
        "impact": 90, "credential access": 90, "exfiltration": 70,
        "privilege escalation": 70, "defense evasion": 70, "lateral movement": 55,
        "command and control": 55, "initial access": 60, "persistence": 50,
        "execution": 45, "collection": 45, "discovery": 35,
        "reconnaissance": 30, "resource development": 30,
    },
    "techniques": {},
}


def _normalize_mitre_map(raw):
    return {
        "version":    str(raw.get("version", "configmap")),
        "default":    int(raw.get("default", 40)),
        "tactics":    {str(k).strip().lower(): int(v)
                       for k, v in (raw.get("tactics") or {}).items()},
        "techniques": {str(k).strip().upper(): int(v)
                       for k, v in (raw.get("techniques") or {}).items()},
    }


def _load_mitre():
    try:
        with open(MITRE_SEVERITY_PATH) as f:
            return _normalize_mitre_map(json.load(f))
    except Exception:
        return _normalize_mitre_map(_MITRE_DEFAULT)


MITRE_SEVERITY = _load_mitre()


# ── Evidence-grade rule registry (Phase 10 / B) ───────────────────────────────
EVIDENCE_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "files", "evidence-rules.json")


def _load_evidence_rules():
    try:
        with open(EVIDENCE_RULES_PATH) as f:
            return {str(k): int(v) for k, v in (json.load(f).get("rules") or {}).items()}
    except Exception:
        return {}


EVIDENCE_RULES = _load_evidence_rules()


def _evidence_grade_score(rule_id):
    if rule_id is None:
        return 0
    if isinstance(rule_id, (int, float)) and not isinstance(rule_id, bool):
        rid = str(int(rule_id))
    elif isinstance(rule_id, str):
        rid = rule_id.strip()
        if not rid or rid.startswith("$"):
            return 0
    else:
        return 0
    return EVIDENCE_RULES.get(rid, 0)


def _load_yara():
    global _YARA, _YARA_TRIED
    if _YARA_TRIED:
        return _YARA
    _YARA_TRIED = True
    try:
        import yara
        files = {}
        if os.path.isdir(YARA_RULES_PATH):
            for fn in sorted(os.listdir(YARA_RULES_PATH)):
                if fn.endswith((".yar", ".yara")):
                    files[fn] = os.path.join(YARA_RULES_PATH, fn)
        if files:
            _YARA = yara.compile(filepaths=files)
    except Exception:
        _YARA = None
    return _YARA


def _deep_get(obj, *paths):
    """Return first non-empty value found at any dotted path in a nested dict."""
    for path in paths:
        cur = obj
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and isinstance(cur, str) and cur.strip() and not cur.strip().startswith("$"):
            return cur.strip()
        if ok and isinstance(cur, (int, float)):
            return cur
    return ""


def _extract_sha256(fields):
    # 1) direct field: syslog decoder, file-drop collector (data.sha256),
    #    Wazuh FIM file-added (syscheck.sha256_after — no agent script)
    v = _deep_get(fields, "data.hash_sha256", "data.sha256", "syscheck.sha256_after")
    if isinstance(v, str) and re.fullmatch(r"[A-Fa-f0-9]{64}", v or ""):
        return v.lower()
    # 2) raw Sysmon eventchannel combined hashes string
    raw = _deep_get(fields, "data.win.eventdata.hashes", "data.win.eventdata.Hashes")
    if isinstance(raw, str):
        m = _SHA256_RE.search(raw)
        if m:
            return m.group(1).lower()
    return ""


def _decode_powershell(command_line):
    """Return the UTF-16LE-decoded payload of a PowerShell -EncodedCommand, or ''."""
    if not isinstance(command_line, str) or not command_line:
        return ""
    m = _ENC_RE.search(command_line)
    if not m:
        return ""
    blob = m.group(1)
    for pad in ("", "=", "==", "==="):
        try:
            raw = base64.b64decode(blob + pad)
            for enc in ("utf-16-le", "utf-8"):
                try:
                    txt = raw.decode(enc)
                    if txt.isprintable() or "\n" in txt:
                        return txt
                except UnicodeDecodeError:
                    continue
        except Exception:
            continue
    return ""


def _run_yara(text):
    rules = _load_yara()
    if not rules or not text:
        return []
    try:
        out = []
        for m in rules.match(data=text):
            meta = m.meta or {}
            out.append({
                "rule": m.rule,
                "score": int(meta.get("score", 0) or 0),
                "severity": str(meta.get("severity", "")),
                "technique": str(meta.get("technique", "")),
            })
        return out
    except Exception:
        return []


_MITRE_TECH_RE = re.compile(r"T\d{4}(?:\.\d{3,})?")


def _mitre_score(mitre_ids, tactics=None):
    def _txt(v):
        if isinstance(v, str):
            return "" if v.strip().startswith("$") else v
        try:
            return json.dumps(v or [])
        except (TypeError, ValueError):
            return ""

    techs = sorted({m.upper() for m in _MITRE_TECH_RE.findall(_txt(mitre_ids))})
    tac_text = _txt(tactics).lower()
    tac_map = MITRE_SEVERITY["tactics"]
    tacs = [name for name in tac_map if name and name in tac_text]
    if not techs and not tacs:
        return 0, [], []
    tech_map = MITRE_SEVERITY["techniques"]
    scores = []
    for t in techs:
        if t in tech_map:
            scores.append(tech_map[t])
        else:
            base = t.split(".")[0]
            if base in tech_map:
                scores.append(tech_map[base])
    for tac in tacs:
        scores.append(tac_map[tac])
    if not scores:
        scores.append(MITRE_SEVERITY["default"])
    score = int(max(0, min(100, max(scores))))
    return score, techs, [t.title() for t in tacs]


def compute_behavior(command_line, mitre_ids=None, tactics=None):
    """
    Decode + analyze a process command line AND fold in MITRE ATT&CK severity.
    Returns {behavior_score, encoded, yara_matches, techniques, tactics,
    mitre_score, yara_score, decoded_preview}. behavior_score = max(yara, mitre,
    encoded-present) and only ever RAISES the final risk via a floor.
    """
    cl = command_line if isinstance(command_line, str) else ""
    decoded = _decode_powershell(cl)
    encoded = bool(decoded) or bool(_ENC_RE.search(cl))
    buf = cl
    if decoded:
        buf = cl + "\n" + decoded
    matches = _run_yara(buf)
    yara_score = max([m["score"] for m in matches], default=0)
    mitre_score, mitre_tech, mitre_tac = _mitre_score(mitre_ids, tactics)
    score = max(yara_score, mitre_score)
    if encoded:
        score = max(score, ENCODED_PRESENT_SCORE)
    yara_tech = {m["technique"] for m in matches if m["technique"]}
    techniques = sorted(yara_tech | set(mitre_tech))
    return {
        "behavior_score": int(max(0, min(100, score))),
        "encoded": encoded,
        "yara_matches": [m["rule"] for m in matches],
        "techniques": techniques,
        "tactics": mitre_tac,
        "mitre_score": mitre_score,
        "yara_score": int(yara_score),
        "decoded_preview": decoded[:160],
    }


def compute_behavior_bytes(raw):
    """Behavioral analysis of raw FILE bytes (Phase 9.2 /analyze-file).
    YARA scans the bytes DIRECTLY so binary PE rules match — a utf-8 decode
    corrupts non-text bytes and loses PE patterns. PowerShell -enc decode + text
    command rules folded in via a best-effort utf-8 view."""
    raw = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8", "replace")
    matches = _run_yara(raw)
    text = raw.decode("utf-8", "ignore")
    decoded = _decode_powershell(text)
    if decoded:
        matches = matches + _run_yara(decoded)
    yara_score = max([m["score"] for m in matches], default=0)
    encoded = bool(decoded) or bool(_ENC_RE.search(text))
    score = yara_score
    if encoded:
        score = max(score, ENCODED_PRESENT_SCORE)
    techniques = sorted({m["technique"] for m in matches if m["technique"]})
    return {
        "behavior_score": int(max(0, min(100, score))),
        "encoded": encoded,
        "yara_matches": sorted({m["rule"] for m in matches}),
        "techniques": techniques,
        "tactics": [],
        "mitre_score": 0,
        "yara_score": int(yara_score),
        "decoded_preview": decoded[:160],
    }


def behavior_floor(behavior_score):
    for thresh, floor in BEHAVIOR_FLOORS:
        if behavior_score >= thresh:
            return floor
    return 0


# POLICY 3.0 — a MITRE tag alone never exceeds auto_promote (mirrors THRESHOLDS).
MITRE_TAG_FLOOR_CAP = 50


def _evidence_floor(content_score, mitre_score):
    """Content evidence (YARA/encoded) → full range ; MITRE tag alone → capped at
    auto_promote (never destructive containment on a classification tag)."""
    content_floor = behavior_floor(content_score)
    mitre_floor = min(behavior_floor(mitre_score), MITRE_TAG_FLOOR_CAP)
    return max(content_floor, mitre_floor)


def _safe_int_min(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _enrichment_score(cortex_max_level, misp_hit):
    """Phase 10 / D — confirmed-malicious IOC reputation as a CONTENT-grade evidence
    score (so it isn't diluted below containment by the weighted average)."""
    lvl = max(0, min(3, _safe_int_min(cortex_max_level)))
    s = 75 if lvl >= 3 else (50 if lvl == 2 else 0)
    if misp_hit:
        s = max(s, 75)
    if lvl >= 3 and misp_hit:
        s = 90
    return s
