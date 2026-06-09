# Demo commands

Step-wise PowerShell scripts to run the DetectForge demo (Windows).

| Script | When | What it does |
|--------|------|--------------|
| `0_setup_once.ps1` | once | Installs the 5 Splunk dashboards |
| `1_reset_demo.ps1` | before each demo | Resets to the clean "before" state — T1078 is a RED blind spot, ALPHV at 60% |
| `2_start_api.ps1`  | each demo | Starts the API + control panel (keep window open) |
| `3_run_scan.ps1`   | each demo | Runs the agent scan; waits until T1078 detections are queued |

## Demo run order
1. `.\commands\1_reset_demo.ps1`
2. `.\commands\2_start_api.ps1`  *(leave running)*
3. In a **new terminal**: `.\commands\3_run_scan.ps1`
4. Open `http://127.0.0.1:8077/` (control panel) and the **Attack Path** dashboard (`http://localhost:8000`).
5. Approve **T1078** on the panel → wait ~40s → the dashboard flips T1078 🔴 → 🟢 (60% → 80%).

Requires: Splunk running locally + the MCP server, with credentials in `.env`.
