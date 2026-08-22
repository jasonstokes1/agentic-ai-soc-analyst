# Agentic AI SOC Analyst

**A tier-1 analyst can triage more alerts in a day than they can meaningfully investigate.** The bottleneck in most SOCs isn't detection. It's the judgment call about which signals deserve a human's attention, and the hours spent writing queries to answer questions that were obvious the moment they were asked.

This is an agentic threat-hunting assistant that closes part of that gap. An analyst asks a question in plain English. The agent decides which log table holds the answer, builds and validates the KQL, runs the hunt, and returns findings mapped to MITRE ATT&CK with graded confidence and recommended actions. It can isolate a compromised host, but only after a human reads the evidence and types `yes`.

Built against a live Microsoft SOC stack: Azure Log Analytics, Microsoft Defender for Endpoint, and Entra ID sign-in telemetry, with Google Gemini as the reasoning layer.

![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-3776AB?logo=python&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-Log%20Analytics-0078D4?logo=microsoftazure&logoColor=white)
![Defender](https://img.shields.io/badge/Microsoft-Defender%20for%20Endpoint-00A4EF?logo=microsoft&logoColor=white)
![Gemini](https://img.shields.io/badge/Google-Gemini-8E75B2?logo=googlegemini&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-C41E3A)

---

![Human-in-the-loop containment gate](screenshots/11-ubuntu-containment-gate.png)

*The agent correlated a `RunCommandExtension`-spawned PowerShell chain pulling remote scripts from an untrusted GitHub repository, mapped it to T1059.001 and T1105, and rated it High confidence. It then stopped and asked for authorization before isolating the host. Declining returns to the prompt without touching the machine.*

---

## What it does

**Plans its own queries and shows its reasoning.** The analyst asks a question. The agent selects the table, the time window, and the fields, then prints its rationale *before* executing anything. "Investigate suspicious process activity on corp-database-a in the last 24 hours" becomes a scoped `DeviceProcessEvents` query with a row cap, and you can see why it chose that before a single record is read.

**Maps to ATT&CK with sub-technique precision.** Not just "credential access." In one run it correlated five failed sign-ins against a single account originating from Georgia, Venezuela, Iraq, and Germany within a short window, recognized error code `50053` as lockout-after-repeated-failure, identified Azure CLI as the client, and mapped it to **T1110.003, Password Spraying** rather than the generic T1110 parent.

**Grades confidence and defends the grade.** The most useful thing an analyst does is decide what *isn't* a threat. Given a PowerShell process running with `-ExecutionPolicy Bypass` and invoking `csc.exe` compilation, a textbook living-off-the-land pattern, the agent traced the initiating process to `SenseIR.exe`, recognized it as Microsoft Defender's own automated investigation tooling, rated the finding **Low**, and recommended `monitor` and `ignore`. In a separate run it found genuinely malicious-looking activity that *matched a known training exercise*, named the exercise, and still flagged the behavior pattern, because attribution and behavior are different questions.

**Recovers from provider failure mid-hunt.** A three-model fallback chain (`gemini-3.1-pro-preview` to `gemini-3.7-flash` to `gemini-3.5-flash-lite`) with error classification on 429, 503, and 404. Every screenshot in this repository shows it recovering from live quota exhaustion, not a simulated failure.

**Knows what a hunt costs before it spends anything.** Pre-flight sizing against each model's context window *and* the tier-specific rate limit, with per-million pricing and an estimated cost for the run. A typical hunt lands between $0.0005 and $0.02.

**Writes an audit trail.** Every finding is appended to `_threats.jsonl`, one JSON object per line, trivially ingestible into a SIEM or notebook, including the full IOC list when the console display is truncated for readability.

---

## Safety and guardrails

Agentic systems that can act on infrastructure need constraints that don't depend on the model behaving well. These are enforced in code, not in prompts:

| Control | Implementation |
|---|---|
| **Table allowlist** | The model can only reach 10 named Log Analytics tables. Anything it invents is rejected before a query is built. |
| **KQL literal sanitization** | Device names, callers, and UPNs returned by the model are treated as untrusted input. Pipes, semicolons, and newlines are stripped before they reach the query string. |
| **Result ceilings** | A hard `MAX_RECORDS` cap prevents an unscoped hunt from pulling tens of thousands of events into the model context. An optional per-query `limit` lets the analyst ask for fewer. |
| **Containment requires three conditions** | Host isolation only becomes available when the query was scoped to a single host, **and** at least one finding is High confidence, **and** the analyst types an explicit `yes`. |
| **Least-privilege token acquisition** | The Defender API token is requested only inside the confirmed-isolation branch. No credential is fetched for a hunt that will never take action. |
| **Cost and capacity gates** | Payloads are sized against context windows and rate limits before the request is sent, with warnings at 80% of any limit. |
| **Schema grounding** | Valid column names for every supported table are supplied to the model, with explicit instructions not to invent fields. |
| **Audit trail** | All findings persist to JSONL regardless of what the analyst decides. |

The agent **recommends**. It never unilaterally acts. Its recommendation vocabulary is a closed set (`pivot`, `create incident`, `monitor`, `ignore`), and the only destructive capability in the system is gated behind a human keystroke.

---

## How it works

```
  Analyst question (natural language)
              |
              v
  +---------------------------+
  |  Tool-call planning       |  Gemini function calling selects table,
  |  (temperature 0.1)        |  timeframe, fields, and scope + rationale
  +---------------------------+
              |
              v
  +---------------------------+
  |  Sanitize + validate      |  Strip KQL metacharacters from model output,
  |                           |  reject any table outside the allowlist
  +---------------------------+
              |
              v
  +---------------------------+
  |  Build + execute KQL      |  Scoped query with row cap against
  |                           |  Azure Log Analytics
  +---------------------------+
              |
              v
  +---------------------------+
  |  Capacity + cost check    |  Size payload against context window and
  |                           |  TPM limits for all three models
  +---------------------------+
              |
              v
  +---------------------------+
  |  Cognitive hunt           |  Table-specific analyst persona, structured
  |  (temperature 0.2)        |  JSON output, automatic model fallback
  +---------------------------+
              |
              v
  +---------------------------+
  |  Findings + persistence   |  MITRE mapping, confidence, IOCs, log lines,
  |                           |  recommendations to console + JSONL
  +---------------------------+
              |
              v
  +---------------------------+
  |  Containment decision     |  High-confidence + host-scoped only.
  |  (human authorization)    |  Analyst reviews all findings, then decides.
  +---------------------------+
```

Each of the ten supported tables has its own analyst persona. `DeviceProcessEvents` looks at execution chains and command lines, `DeviceNetworkEvents` looks for C2 and exfiltration, `DeviceRegistryEvents` looks for persistence and defense evasion. The hunt prompt is assembled per-table rather than using a single generic instruction.

---

## Demonstrated across four platforms

The same codebase, run against the same live Azure environment, from four different operating environments. Each demonstrates a different area of SOC work.

### macOS Terminal, network flow analysis

Tenant-wide NSG flow log hunt. The agent identified sustained inbound scanning against two internal VMs across SSH, Telnet, RDP, SMB, and Redis ports, aggregated 8 external source IPs as IOCs, mapped it to **T1595.001 (Active Scanning: Scanning IP Blocks)**, and correctly read `FlowStatus_s = 'A'` and `FlowDirection_s = 'I'` as *allowed inbound*, meaning the traffic reached its targets and the NSG rules needed review.

![macOS finding](screenshots/02-macos-nsg-hunt-findings.png)

<details>
<summary>Full session: planning, KQL construction, and model fallback</summary>

![macOS pipeline](screenshots/01-macos-nsg-hunt-pipeline.png)

</details>

### Windows PowerShell, endpoint triage and false-positive reduction

Endpoint process hunt that found a suspicious-looking PowerShell execution chain and then argued itself down to Low confidence after tracing the parent process to Defender's own IR tooling.

![PowerShell triage](screenshots/05-windows-powershell-triage.png)

<details>
<summary>Full session: planning and model fallback</summary>

![PowerShell planning](screenshots/03-windows-powershell-planning.png)
![PowerShell fallback](screenshots/04-windows-powershell-fallback.png)

</details>

### Visual Studio 2026, identity and credential access

Sign-in log analysis run under the Visual Studio debugger, with the source visible alongside the output. Detected repeated account lockouts from four countries against a single account and mapped it to **T1110.003 (Password Spraying)**.

![Visual Studio finding](screenshots/08-visualstudio-fallback-finding.png)

<details>
<summary>Full session: source, validation, KQL, and IOCs</summary>

![VS planning](screenshots/06-visualstudio-planning.png)
![VS validation and KQL](screenshots/07-visualstudio-validation-kql.png)
![VS IOCs and recommendations](screenshots/09-visualstudio-iocs-recommendations.png)

</details>

### Ubuntu 24.04 on Azure, host-scoped hunt with containment

Headless Linux VM using device-code authentication, since a server has no browser for interactive sign-in. Host-scoped hunt against `corp-database-a` that surfaced remote script retrieval and execution via Azure's `RunCommandExtension`, then presented the containment decision.

![Ubuntu containment gate](screenshots/11-ubuntu-containment-gate.png)

<details>
<summary>Full session: device-code auth, planning, and execution</summary>

![Ubuntu hunt](screenshots/10-ubuntu-host-scoped-hunt.png)

</details>

---

## Setup

**Prerequisites**

- Python 3.11 or later
- An Azure Log Analytics workspace with Defender for Endpoint and/or Entra ID diagnostic data
- A Google Gemini API key
- Azure credentials with Log Analytics Reader on the target workspace
- For containment: Defender for Endpoint API permissions (`Machine.Isolate`)

**Install**

```bash
git clone https://github.com/jasonstokes1/agentic-ai-soc-analyst.git
cd agentic-ai-soc-analyst

python3 -m venv agent_env
source agent_env/bin/activate          # Windows: .\agent_env\Scripts\Activate.ps1

pip install -r requirements.txt
```

**Configure**

```bash
cp _keys.example.py _keys.py
```

Then edit `_keys.py` with your Gemini API key and Log Analytics workspace ID. This file is gitignored and must never be committed.

**Run**

```bash
python3 _main.py
```

Then ask a question:

```
Can you check for any malicious network flows across our NSGs in the last 12 hours?
Investigate suspicious process activity on corp-database-a in the last 24 hours.
Hunt for failed sign-in attempts or unusual authentication activity in the last 24 hours.
```

**Tested on**

| Environment | Python | Azure auth |
|---|---|---|
| macOS (Terminal) | 3.14 | `InteractiveBrowserCredential` |
| Windows 11 (PowerShell) | 3.11 | `InteractiveBrowserCredential` |
| Windows 11 (Visual Studio 2026) | 3.11 | `InteractiveBrowserCredential` |
| Ubuntu 24.04 on Azure (SSH) | 3.12 | `DeviceCodeCredential` |

---

## Project structure

```
_main.py                 Session loop and containment decision point
EXECUTOR.py              KQL construction, Log Analytics queries, Gemini calls,
                         model fallback chain, Defender isolation API
PROMPT_MANAGEMENT.py     Per-table analyst personas, finding schema, tool definition
GUARDRAILS.py            Table and model allowlists, tier limits, pricing data
MODEL_MANAGEMENT.py      Token estimation, capacity checks, cost projection
UTILITIES.py             Input sanitization, finding display, JSONL persistence
_keys.example.py         Template for local credentials (copy to _keys.py)
requirements.txt         Pinned dependencies
screenshots/             Demonstration runs across four platforms
```

---

## Engineering notes

Building this surfaced several failure modes that are specific to putting an LLM in the query-planning path. Each is documented here because understanding how the tool fails is as relevant as knowing what it does when it works.

**Sentinel values silently returning zero rows.** The tool schema marks `device_name` and `user_principal_name` as required, so a tenant-wide hunt forced the model to invent a placeholder, sometimes `*`, sometimes `all`. KQL `startswith` is a literal prefix match, so the query looked for hostnames beginning with an asterisk and returned nothing, with no error. Fixed by recognizing a set of unscoped sentinels and omitting the `where` clause entirely.

**Hallucinated column names.** The model requested `Account` from `DeviceProcessEvents`, which has `AccountName`. Log Analytics rejected the query with a semantic error. Fixed by grounding the tool-selection prompt with the valid column list for every supported table.

**Unbounded result sets.** An unfiltered tenant-wide process query returned 63,882 records, roughly 7.3 million tokens, 3.6x the largest model's context window and 29x the per-minute quota. The capacity checker correctly flagged it and the code proceeded anyway, burning three API calls to learn what it already knew. Fixed with a hard row cap plus an optional per-query limit.

**Invalid JSON escapes from Windows paths.** Structured output containing `C:\ProgramData\...` produced invalid JSON escape sequences, and `json.loads()` failed after a hunt had already succeeded. This disproportionately affected `DeviceProcessEvents`, where command lines are backslash-heavy. Fixed with a repair pass that escapes backslashes not already part of a valid escape sequence.

**Containment prompt firing per finding.** The isolation gate originally prompted once for every high-confidence finding, so declining the first meant being asked again immediately. Redesigned to collect all high-confidence findings for the host, present them together, and request a single authorization decision, which is also better tradecraft since the analyst decides with the full picture rather than incrementally.

### Current limitations

- **`take` is non-deterministic.** KQL's `take` returns an arbitrary subset rather than the most recent or most relevant rows, so two identical hunts can analyze different data. A `top ... by TimeGenerated desc` ordering would be more useful.
- **Findings vary between runs.** Different models in the fallback chain have different sensitivity, and the same model regenerates rather than recalling. High-confidence findings have been consistent. Marginal ones less so.
- **Credential type is hardcoded per platform.** Desktop environments use interactive browser auth, the headless VM uses device code. This should be configuration rather than a code change.
- **Field validation is deferred.** Table names are validated against an allowlist. Field names are not, and rely on Log Analytics' own schema enforcement to reject invalid columns.
- **Token counting is approximate.** Pre-flight estimation uses a character-length heuristic rather than the SDK's tokenizer, trading precision for avoiding an extra API round-trip before every hunt.

---

## Scope and authorized use

This was built and tested exclusively against a purpose-built cyber range, an isolated Azure environment with intentionally exposed hosts, generating genuine attack telemetry from internet-wide scanning. All hostnames, accounts, and internal IP addresses shown in this repository belong to that lab.

This tool queries security telemetry and can take containment action against endpoints. **Do not run it against any environment you are not explicitly authorized to assess.** The containment path requires Defender API permissions that should be scoped deliberately, and the human-in-the-loop gate should not be removed.
