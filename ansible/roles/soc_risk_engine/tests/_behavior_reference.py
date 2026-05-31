# Standalone copy of the NEW risk-engine logic for local validation.
# Mirrors exactly what will go into risk-engine-app.py.j2 (no Jinja here).
import base64
import json
import re

# ── Behavioral floors (configurable via group_vars → rendered constants) ──────
# Maps a behavioral severity score (0-100, from YARA/decode) to a MINIMUM final
# risk score. The engine takes max(weighted_scenario_score, floor): behavior can
# only RAISE the score, never lower it → existing tuned scores stay intact.
BEHAVIOR_FLOORS = [
    (90, 90),   # critical (AMSI bypass, cred dumping)        → escalate
    (70, 75),   # high (download cradle, IEX remote, inject)  → contained
    (50, 50),   # medium (encoded command present)            → auto_promoted
]                # NB: suspicious-flags-only (score 40) stays below → no floor,
                 # surfaced in yara_matches for analyst context but no forced case.
# Base score attributed to "an encoded/obfuscated command is present" even when
# the decoded content matches no malicious rule (obfuscation is itself a weak
# signal worth a human review = auto_promote tier).
ENCODED_PRESENT_SCORE = 50

YARA_RULES_PATH = "/config/yara"

_ENC_RE = re.compile(r"-e(?:nc|ncodedcommand|ncoded)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_SHA256_RE = re.compile(r"SHA256=([A-Fa-f0-9]{64})")
_URL_RE = re.compile(r"https?://[^\s'\"<>|]+", re.I)

# yara compiled handle (lazy, cached). None if yara unavailable or no rules.
_YARA = None
_YARA_TRIED = False


def _load_yara():
    global _YARA, _YARA_TRIED
    if _YARA_TRIED:
        return _YARA
    _YARA_TRIED = True
    try:
        import os
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
    # 1) already-split field (syslog selftest decoder)
    v = _deep_get(fields, "data.hash_sha256")
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


def compute_behavior(command_line):
    """
    Decode + analyze a process command line. Returns:
      {behavior_score, encoded, yara_matches, techniques, decoded_preview}
    behavior_score is 0-100 and only ever RAISES the final risk via a floor.
    """
    cl = command_line if isinstance(command_line, str) else ""
    decoded = _decode_powershell(cl)
    encoded = bool(decoded) or bool(_ENC_RE.search(cl))
    buf = cl
    if decoded:
        buf = cl + "\n" + decoded
    matches = _run_yara(buf)
    score = max([m["score"] for m in matches], default=0)
    if encoded:
        score = max(score, ENCODED_PRESENT_SCORE)
    techniques = sorted({m["technique"] for m in matches if m["technique"]})
    return {
        "behavior_score": int(max(0, min(100, score))),
        "encoded": encoded,
        "yara_matches": [m["rule"] for m in matches],
        "techniques": techniques,
        "decoded_preview": decoded[:160],
    }


def behavior_floor(behavior_score):
    for thresh, floor in BEHAVIOR_FLOORS:
        if behavior_score >= thresh:
            return floor
    return 0
