"""Prepare SPL fine-tuning dataset for Together AI.

Exports seed baseline detections (and optionally ESCU rules) as instruction-tuning
pairs in Together AI chat JSONL format.

Usage:
    uv run python scripts/prepare_finetune_data.py
    uv run python scripts/prepare_finetune_data.py --escu-dir /path/to/security_content/detections

Output: spl_finetune.jsonl  (~16+ examples from seed, more if ESCU dir provided)

Then fine-tune on Together AI:
    pip install together
    together files upload spl_finetune.jsonl
    together fine-tuning create \\
        --training-file <file-id> \\
        --model togethercomputer/Llama-3.1-8b-Instruct \\
        --n-epochs 3 \\
        --learning-rate 1e-5
    # Wait ~30-60 min, cost ~$3-5 for 8b on this dataset size

After completion set in .env:
    FINETUNED_MODEL_ID=<your-account>/<job-output-model-id>
    USE_FINETUNED_SPL=true
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Seed baseline rules — each entry becomes one training example
# These mirror scripts/seed_baseline.py; technique metadata is embedded in comments
SEED_EXAMPLES = [
    {
        "technique_id": "T1566.001",
        "technique_name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Detect email attachments with executable or macro-enabled extensions",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*.exe*" OR CommandLine="*.vbs*" OR CommandLine="*.js*" OR CommandLine="*.hta*") | stats count by host,user,CommandLine | where count < 5 | eval rule_name="T1566.001 - Spearphishing Attachment"',
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Detect encoded or suspicious PowerShell execution",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*") | stats count by host,user,CommandLine | eval rule_name="T1059.001 - PowerShell Execution"',
    },
    {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Detect LSASS memory access via mimikatz or similar tools",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4656 ObjectName="*lsass*" | stats count by host,user,ObjectName,ProcessName | where count < 10 | eval rule_name="T1003.001 - LSASS Credential Dumping"',
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Detect mass file modification consistent with ransomware encryption",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4663 (ObjectName="*.encrypted*" OR ObjectName="*.locked*" OR ObjectName="*.crypto*") | stats count by host,user | where count > 50 | eval rule_name="T1486 - Ransomware Encryption"',
    },
    {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Detect new scheduled task creation",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4698 | stats count by host,user,TaskName,TaskContent | eval rule_name="T1053.005 - Scheduled Task Creation"',
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Detect cross-process memory writes indicative of injection",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*VirtualAllocEx*" OR CommandLine="*WriteProcessMemory*" OR CommandLine="*CreateRemoteThread*") | stats count by host,user,CommandLine | eval rule_name="T1055 - Process Injection"',
    },
    {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Detect system reconnaissance commands",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*systeminfo*" OR CommandLine="*whoami*" OR CommandLine="*hostname*" OR CommandLine="*ipconfig*") | stats count by host,user,CommandLine | where count > 3 | eval rule_name="T1082 - System Discovery"',
    },
    {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Detect unusual outbound HTTP/S to non-standard ports",
        "spl": 'index=botsv3 sourcetype="stream:tcp" dest_port!=80 dest_port!=443 dest_port!=8080 app=http | stats count by src_ip,dest_ip,dest_port | where count > 10 | eval rule_name="T1071.001 - C2 Web Protocol"',
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Detect large data transfers over DNS or ICMP",
        "spl": 'index=botsv3 sourcetype="stream:dns" | stats sum(bytes_out) as total_bytes by src_ip,query | where total_bytes > 100000 | eval rule_name="T1048 - DNS Exfiltration"',
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Detect web application attack patterns in access logs",
        "spl": 'index=botsv3 sourcetype="access_combined" (uri_path="*../../../*" OR uri_path="*<script>*" OR uri_path="*UNION+SELECT*" OR uri_path="*;cat+/*") | stats count by clientip,uri_path,status | eval rule_name="T1190 - Web App Exploit"',
    },
    {
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Detect local user account creation",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4720 | stats count by host,user,TargetUserName,SubjectUserName | eval rule_name="T1136.001 - Local Account Created"',
    },
    {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Detect privilege escalation via group membership changes",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode IN (4728,4732,4756) | stats count by host,user,TargetUserName,GroupName | eval rule_name="T1098 - Account Manipulation"',
    },
    {
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Detect disabling of Windows Defender or security services",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688 (CommandLine="*Set-MpPreference*DisableRealtimeMonitoring*" OR CommandLine="*sc stop*WinDefend*" OR CommandLine="*net stop*") | stats count by host,user,CommandLine | eval rule_name="T1562.001 - Disable Defenses"',
    },
    {
        "technique_id": "T1569.002",
        "technique_name": "System Services: Service Execution",
        "tactic": "Execution",
        "description": "Detect service creation used for lateral movement execution",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=7045 | stats count by host,ServiceName,ImagePath,StartType | eval rule_name="T1569.002 - Malicious Service Execution"',
    },
    {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Detect repeated authentication failures indicating brute force",
        "spl": 'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4625 | bucket _time span=5m | stats count by _time,host,user,src_ip | where count > 10 | eval rule_name="T1110.001 - Password Brute Force"',
    },
    {
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Detect network scanning and host enumeration activity",
        "spl": 'index=botsv3 sourcetype="stream:ip" | stats dc(dest_ip) as unique_dests by src_ip | where unique_dests > 20 | eval rule_name="T1018 - Network Host Discovery"',
    },
]

SYSTEM_PROMPT = (
    "You are a Splunk detection engineer. "
    "Given a MITRE ATT&CK technique and environment context, write a Splunk SPL detection rule. "
    "Return only valid SPL — no explanation, no markdown fences, no comments."
)


def build_user_prompt(example: dict, index: str = "botsv3") -> str:
    return (
        f"Write a Splunk SPL detection rule for MITRE ATT&CK {example['technique_id']} "
        f"({example['technique_name']}), tactic: {example['tactic']}.\n\n"
        f"Detection goal: {example['description']}\n\n"
        f"Search index={index}. Return only valid SPL."
    )


def to_chat_jsonl(example: dict) -> dict:
    """Together AI chat fine-tuning format."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(example)},
            {"role": "assistant", "content": example["spl"]},
        ]
    }


def load_escu_yaml(escu_dir: Path) -> list[dict]:
    """Load detections from Splunk Security Content (ESCU) YAML files."""
    try:
        import yaml
    except ImportError:
        print("pyyaml not installed — skipping ESCU. Run: uv add pyyaml", file=sys.stderr)
        return []

    examples = []
    for yaml_file in escu_dir.rglob("*.yml"):
        try:
            doc = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                continue
            search = doc.get("search", "")
            technique_ids = []
            for ref in doc.get("tags", {}).get("mitre_attack_id", []):
                technique_ids.append(ref)
            if not search or not technique_ids:
                continue
            # Skip non-SPL searches
            if not any(k in search for k in ("index=", "sourcetype=", "| tstats")):
                continue
            examples.append({
                "technique_id": technique_ids[0],
                "technique_name": doc.get("name", technique_ids[0]),
                "tactic": (doc.get("tags", {}).get("kill_chain_phases", ["unknown"])[0]),
                "description": doc.get("description", "")[:300],
                "spl": search.strip(),
            })
        except Exception:
            continue
    print(f"Loaded {len(examples)} examples from ESCU at {escu_dir}")
    return examples


def main():
    parser = argparse.ArgumentParser(description="Prepare SPL fine-tuning JSONL for Together AI")
    parser.add_argument("--escu-dir", type=Path, default=None, help="Path to splunk/security_content/detections")
    parser.add_argument("--output", type=Path, default=Path("spl_finetune.jsonl"), help="Output JSONL file")
    args = parser.parse_args()

    examples = list(SEED_EXAMPLES)

    if args.escu_dir:
        escu_examples = load_escu_yaml(args.escu_dir)
        examples.extend(escu_examples)

    # Deduplicate by (technique_id, spl[:50])
    seen = set()
    unique = []
    for ex in examples:
        key = (ex["technique_id"], ex["spl"][:50])
        if key not in seen:
            seen.add(key)
            unique.append(ex)

    records = [to_chat_jsonl(ex) for ex in unique]

    args.output.write_text(
        "\n".join(json.dumps(r) for r in records),
        encoding="utf-8",
    )
    print(f"Wrote {len(records)} training examples → {args.output}")
    print()
    print("Next steps:")
    print("  pip install together")
    print(f"  together files upload {args.output}")
    print("  together fine-tuning create \\")
    print("      --training-file <file-id> \\")
    print("      --model togethercomputer/Llama-3.1-8b-Instruct \\")
    print("      --n-epochs 3")
    print()
    print("After job completes, set in .env:")
    print("  FINETUNED_MODEL_ID=<your-account>/<model-id>")
    print("  USE_FINETUNED_SPL=true")


if __name__ == "__main__":
    main()
