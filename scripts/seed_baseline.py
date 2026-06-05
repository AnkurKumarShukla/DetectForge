"""Seed a realistic 'before' detection baseline into Splunk.

BOTS v3 ships as raw event data with NO pre-built security detections, so a
fresh environment starts at ~0% coverage and DetectForge has nothing to
classify. This installs a believable set of existing detection rules — the
kind a real (somewhat neglected) SOC would already have — so the demo can show:

  - A realistic 'before' coverage picture (DetectForge classifies these).
  - The attack-path graph with COVERED nodes AND deliberate blind spots.

It DELIBERATELY leaves the headline kill-chain gaps open:
  - T1078 Valid Accounts        (ALPHV step 2 — the entry blind spot)
  - T1021 Remote Services        (ALPHV step 3 — lateral-movement blind spot)
so DetectForge has a dramatic, true gap to close on stage.

Run:  uv run python scripts/seed_baseline.py
      uv run python scripts/seed_baseline.py --remove   # tear down

All SPL targets real BOTS v3 sourcetypes. The searches only need to exist and
classify; they are the org's pre-existing rules, tagged `security_baseline`
(NOT `detectforge`) so they stay distinct from DetectForge-generated rules.
"""
import sys

# Make the package importable when run as a script.
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.splunk.rest_client import SplunkRestClient  # noqa: E402

BASE_TAG = "security_baseline"

# (search_name, technique_id, technique_name, tactic, spl)
# Names + SPL are written to be unambiguous so the classifier maps them cleanly.
SEED_DETECTIONS: list[tuple[str, str, str, str, str]] = [
    (
        "Phishing - Suspicious Inbound Attachment",
        "T1566", "Phishing", "initial-access",
        'index=botsv3 sourcetype="stream:smtp" '
        '("attachment" OR content_type="application/*") '
        '| rex field=attach_filename "(?<ext>\\.[^.]+)$" '
        '| search ext IN (".exe",".js",".vbs",".scr",".zip",".docm") '
        '| stats count by src_user, receiver, attach_filename '
        '| where count > 0',
    ),
    (
        "Brute Force - Excessive Failed Windows Logons",
        "T1110", "Brute Force", "credential-access",
        'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4625 '
        '| stats count by Account_Name, src '
        '| where count > 10',
    ),
    (
        "Credential Dumping - LSASS Process Access",
        "T1003", "OS Credential Dumping", "credential-access",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=10 TargetImage="*lsass.exe" '
        '| stats count by SourceImage, GrantedAccess, host '
        '| where count > 0',
    ),
    (
        "Ransomware - Mass File Modification by Single Process",
        "T1486", "Data Encrypted for Impact", "impact",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=11 '
        '| bucket _time span=5m '
        '| stats dc(TargetFilename) as files_touched by _time, Image, host '
        '| where files_touched > 100',
    ),
    (
        "Suspicious Command Shell Execution",
        "T1059", "Command and Scripting Interpreter", "execution",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe") '
        '| stats count by host, Image, CommandLine, User',
    ),
    (
        "User Execution - Office Application Spawning Shell",
        "T1204", "User Execution", "execution",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe") '
        '(Image="*\\cmd.exe" OR Image="*\\powershell.exe") '
        '| stats count by host, ParentImage, Image, CommandLine',
    ),
    (
        "WMI-Based Process Execution",
        "T1047", "Windows Management Instrumentation", "execution",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 ParentImage="*\\wmiprvse.exe" '
        '| stats count by host, Image, CommandLine',
    ),
    (
        "Scheduled Task Created",
        "T1053.005", "Scheduled Task", "persistence",
        'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4698 '
        '| stats count by host, Task_Name, Account_Name',
    ),
    (
        "New Local User Account Created",
        "T1136", "Create Account", "persistence",
        'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4720 '
        '| stats count by host, Target_Account_Name, Subject_Account_Name',
    ),
    (
        "Registry Run Key Persistence",
        "T1547.001", "Registry Run Keys / Startup Folder", "persistence",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=13 TargetObject="*\\CurrentVersion\\Run*" '
        '| stats count by host, Image, TargetObject, Details',
    ),
    (
        "C2 - Suspicious DNS Query Volume (Beaconing)",
        "T1071.004", "Application Layer Protocol: DNS", "command-and-control",
        'index=botsv3 sourcetype="stream:dns" '
        '| stats count dc(query) as unique_queries by src_ip '
        '| where count > 500 AND unique_queries > 200',
    ),
    (
        "Network Service Scanning - Internal Port Sweep",
        "T1046", "Network Service Discovery", "discovery",
        'index=botsv3 sourcetype="cisco:asa" '
        '| stats dc(dest_port) as ports_touched by src_ip, dest_ip '
        '| where ports_touched > 20',
    ),
    (
        "Inhibit Recovery - Volume Shadow Copy Deletion",
        "T1490", "Inhibit System Recovery", "impact",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 (Image="*\\vssadmin.exe" OR Image="*\\wbadmin.exe") '
        'CommandLine="*delete*" '
        '| stats count by host, Image, CommandLine',
    ),
    (
        "Remote System Discovery via net.exe",
        "T1018", "Remote System Discovery", "discovery",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 Image="*\\net.exe" (CommandLine="*view*" OR CommandLine="*group*") '
        '| stats count by host, CommandLine, User',
    ),
    (
        "Process Discovery via tasklist",
        "T1057", "Process Discovery", "discovery",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 Image="*\\tasklist.exe" '
        '| stats count by host, CommandLine, User',
    ),
    (
        "Impair Defenses - Windows Defender Tampering",
        "T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion",
        'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        'EventCode=1 CommandLine="*Set-MpPreference*" CommandLine="*Disable*" '
        '| stats count by host, CommandLine, User',
    ),
]

# NOTE: deliberately ABSENT (DetectForge's headline gaps to close on stage).
# We leave the ENTIRE T1078 (Valid Accounts) family open — including cloud —
# so the ALPHV/Change-Healthcare story shows two consecutive blind spots:
#   T1078 Valid Accounts   — ALPHV step 2 entry blind spot
#   T1021 Remote Services  — ALPHV step 3 lateral-movement blind spot


def install(rest: SplunkRestClient) -> None:
    ok = 0
    for name, tid, tname, tactic, spl in SEED_DETECTIONS:
        # Idempotent: remove any prior copy first.
        try:
            rest.delete_saved_search(name)
        except Exception:
            pass
        # Prepend an ATT&CK header comment. The MCP saved-search API returns the
        # SPL (but not the description), so this is where the annotation must live
        # for DetectForge's classifier to read it as ground truth.
        annotated_spl = f"``` ATTACK_TECHNIQUE={tid} ATTACK_TACTIC={tactic} ```\n{spl}"
        try:
            rest.create_saved_search(
                name=name, spl=annotated_spl,
                description=f"Baseline detection for {tid} {tname}",
                technique_id=tid, tactic=tactic, industry="healthcare",
                base_tag=BASE_TAG,
            )
            ok += 1
            print(f"  [+] {name}  ->  {tid} {tname}")
        except Exception as e:
            print(f"  [!] FAILED {name}: {repr(e)[:160]}")
    print(f"\nInstalled {ok}/{len(SEED_DETECTIONS)} baseline detections (tag={BASE_TAG}).")
    print("Deliberate gaps left open: T1078 Valid Accounts, T1021 Remote Services.")


def purge_detectforge_rules(rest: SplunkRestClient) -> None:
    """Delete saved searches DetectForge itself deployed in prior runs.

    These are named 'DetectForge - <technique> - ...'. If left behind, the next
    scan's classifier reads them as existing coverage — silently closing the very
    gaps the demo is meant to leave open (e.g. T1078 wrongly shows COVERED).
    """
    import httpx
    from core.config import get_settings
    s = get_settings()
    auth = (s.splunk_username, s.splunk_password)
    url = f"{s.splunk_url}/servicesNS/-/-/saved/searches"
    try:
        r = httpx.get(url, params={"count": 0, "output_mode": "json", "search": "DetectForge"},
                      auth=auth, verify=False, timeout=30)
        names = [e["name"] for e in r.json().get("entry", []) if e["name"].startswith("DetectForge")]
    except Exception as e:
        print(f"  [!] could not list DetectForge rules: {repr(e)[:120]}")
        return
    n = 0
    for name in names:
        try:
            rest.delete_saved_search(name)
            n += 1
            print(f"  [-] purged {name}")
        except Exception:
            pass
    print(f"Purged {n} DetectForge-deployed rules.")


def remove(rest: SplunkRestClient) -> None:
    n = 0
    for name, *_ in SEED_DETECTIONS:
        try:
            rest.delete_saved_search(name)
            n += 1
            print(f"  [-] removed {name}")
        except Exception:
            pass
    print(f"\nRemoved {n} baseline detections.")
    purge_detectforge_rules(rest)


if __name__ == "__main__":
    rest = SplunkRestClient()
    if not rest.test_connectivity():
        print("ERROR: cannot reach Splunk REST API. Check SPLUNK_URL/credentials in .env")
        sys.exit(1)
    if "--remove" in sys.argv:
        remove(rest)
    else:
        install(rest)
