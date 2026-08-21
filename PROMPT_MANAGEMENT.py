from colorama import Fore

FORMATTING_INSTRUCTIONS = """
Return your findings in the following format:
{
"findings":
  [
    <finding 1>,
    <finding 2>,
    <finding n>
  ]
}

If there are no findings, return an empty array:
{
  "findings": []
}

Here is the schema you are to use, it contains an example of a single finding:
{
  "findings":
  [
    {
      "title": "Brief title describing the suspicious activity",
      "description": "Detailed explanation of why this activity is suspicious, including context from the logs",
      "mitre": {
        "tactic": "e.g., Execution",
        "technique": "e.g., T1059",
        "sub_technique": "e.g., T1059.001",
        "id": "e.g., T1059, T1059.001",
        "description": "Description of the MITRE technique/sub-technique used"
      },
      "log_lines": [
        "Relevant line(s) from the logs that triggered the suspicion"
      ],
      "confidence": "Low | Medium | High",
      "recommendations": [
        "pivot", 
        "create incident", 
        "monitor", 
        "ignore"
      ],
      "indicators_of_compromise": [
        "Any IOCs (IP, domain, hash, filename, etc.) found in the logs"
      ],
      "tags": [
        "privilege escalation", 
        "persistence", 
        "data exfiltration", 
        "C2", 
        "credential access", 
        "unusual command", 
        "reconnaissance", 
        "malware", 
        "suspicious login"
      ],
      "notes": "Optional analyst notes or assumptions made during detection"
    }
  ]
}
"""

THREAT_HUNT_PROMPTS = {
"GeneralThreatHunter": "You are a top-tier Threat Hunting Analyst AI focused on Microsoft Defender for Endpoint (MDE) host data...",
"DeviceProcessEvents": "You are an expert Threat Hunting AI analyzing MDE DeviceProcessEvents. Focus on process execution chains, command-line usage, and suspicious binaries.",
"DeviceNetworkEvents": "You are an expert Threat Hunting AI analyzing MDE DeviceNetworkEvents. Focus on signs of command & control, lateral movement, or exfiltration over the network.",
"DeviceLogonEvents": "You are an expert Threat Hunting AI analyzing MDE DeviceLogonEvents. Focus on abnormal authentication behavior and lateral movement.",
"DeviceRegistryEvents": "You are an expert Threat Hunting AI analyzing MDE DeviceRegistryEvents. Focus on persistence, defense evasion, and configuration tampering via registry keys.",
"AlertEvidence": "You are a Threat Hunting AI analyzing MDE AlertEvidence entries. Your goal is to correlate evidence from alerts to support or refute active malicious behavior.",
"DeviceFileEvents": "You are a Threat Hunting AI analyzing MDE DeviceFileEvents. Focus on suspicious file creation, modification, and movement.",
"AzureActivity": "You are a Threat Hunting AI analyzing AzureActivity (Azure Monitor activity log) for control-plane operations. Focus on resource creation, role changes, failures, or unusual carveouts.",
"SigninLogs": "You are a Threat Hunting AI analyzing SigninLogs (Azure AD sign-in events). Detect authentication anomalies and credential abuse.",
"AuditLogs": "You are a Threat Hunting AI analyzing AuditLogs (Azure AD audit events). Focus on directory and identity changes.",
"AzureNetworkAnalytics_CL": "You are a Threat Hunting AI analyzing AzureNetworkAnalytics_CL (NSG flow logs via traffic analytics). Focus on anomalous network flows and malicious traffic types."
}

SYSTEM_PROMPT_THREAT_HUNT = {
    "role": "system",
    "content": (
        "You are a cybersecurity threat hunting AI trained to support SOC analysts by identifying suspicious or malicious activity in log data from Microsoft Defender for Endpoint (MDE), Azure Active Directory (AAD), and Azure resource logs.\n\n"
        "You are expected to:\n"
        "- Accurately interpret logs from a variety of sources.\n"
        "- Map activity to MITRE ATT&CK tactics.\n"
        "- Provide detection confidence (High, Medium, Low).\n"
        "- Highlight Indicators of Compromise (IOCs).\n"
        "- Recommend defender actions.\n\n"
        "Avoid hallucinating data. You are assisting skilled analysts."
    )}

SYSTEM_PROMPT_TOOL_SELECTION = {
    "role": "system",
    "content": ("""
      You are part of a tools/function call.
      Your purpose is to take natural, threat-hunt related human language from a human SOC Analyst
      and figure out which tables to investigate as well as figure out what the request/concern is
      about (user account related, device/host related, firewall/NSG related, etc.).

      CRITICAL: Only request fields that actually exist in the target table. Never invent column
      names. Use ONLY the fields listed below for each table:

      DeviceProcessEvents: TimeGenerated, DeviceName, AccountName, AccountDomain, ProcessCommandLine,
        InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath, SHA256
      DeviceNetworkEvents: TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, LocalIP,
        LocalPort, Protocol, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
      DeviceLogonEvents: TimeGenerated, DeviceName, AccountName, AccountDomain, LogonType,
        ActionType, RemoteIP, RemoteDeviceName, IsLocalAdmin
      DeviceFileEvents: TimeGenerated, DeviceName, FileName, FolderPath, SHA256, ActionType,
        InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
      DeviceRegistryEvents: TimeGenerated, DeviceName, RegistryKey, RegistryValueName,
        RegistryValueData, ActionType, InitiatingProcessFileName, AccountName
      AlertInfo: TimeGenerated, AlertId, Title, Category, Severity, ServiceSource, DetectionSource
      AlertEvidence: TimeGenerated, AlertId, Title, Categories, EntityType, DeviceName, AccountName,
        FileName, SHA256, RemoteIP, RemoteUrl
      SigninLogs: TimeGenerated, UserPrincipalName, UserDisplayName, IPAddress, ResultType,
        ResultDescription, AppDisplayName, ClientAppUsed, Location
      AzureActivity: TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue,
        ResourceGroup, ResourceProviderValue, Level
      AzureNetworkAnalytics_CL: TimeGenerated, FlowStartTime_t, FlowType_s, SrcIP_s, DestIP_s,
        DestPort_d, FlowStatus_s, FlowDirection_s

      Do not invent non-existent schema fields such as MaliciousIP_s or Account.
      Note that DeviceProcessEvents uses AccountName, not Account.

      If the request is tenant-wide (not scoped to one host or user), set device_name and
      user_principal_name to "*".

      If no timeframe is specified by the user, choose 4 days (96 hours).
""")
}

TOOL_DEF = {
    "function_declarations": [
        {
            "name": "query_log_analytics",
            "description": "Query a Log Analytics table using KQL.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "table_name": {"type": "STRING", "description": "Log Analytics table to query. Examples: DeviceProcessEvents, SigninLogs, AzureNetworkAnalytics_CL"},
                    "device_name": {"type": "STRING", "description": "The DeviceName to filter by"},
                    "caller": {"type": "STRING", "description": "Email address of the user who performed the operation"},
                    "user_principal_name": {"type": "STRING", "description": "The email address, UPN, username"},
                    "time_range_hours": {"type": "INTEGER", "description": "How far back to search"},
                    "fields": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "List of fields to return"},
                    "about_individual_user": {"type": "BOOLEAN", "description": "Query is about an individual user"},
                    "about_individual_host": {"type": "BOOLEAN", "description": "Query is about a specific host"},
                    "about_network_security_group": {"type": "BOOLEAN", "description": "Query is about a firewall or NSG"},
                    "limit": {"type": "INTEGER", "description": "Maximum number of log rows to return. Use the number the analyst asked for (e.g. 'top 3 rows' = 3). If unspecified, use 500."},
                    "rationale": {"type": "STRING", "description": "Your rationale for choosing these properties"}
                },
                "required": [
                    "table_name", "device_name", "time_range_hours", "fields",
                    "caller", "user_principal_name", "about_individual_user",
                    "about_individual_host", "about_network_security_group", "limit", "rationale"
                ]
            }
        }
    ]
}

def get_user_message():
    prompt = ""
    print("\n"*2)  # Reduced from 20 to 2 lines to remove the giant gap
    user_input = input(f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}").strip()
    if user_input:
        prompt = user_input
    user_message = {"role": "user", "content": prompt}
    return user_message

def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str) -> dict:
    print(f"{Fore.LIGHTGREEN_EX}Building threat hunt prompt/instructions...\n")
    instructions = THREAT_HUNT_PROMPTS.get(table_name, "")
    full_prompt = (
        f"User request:\n{user_prompt}\n\n"
        f"Threat Hunt Instructions:\n{instructions}\n\n"
        f"Formatting Instructions: \n{FORMATTING_INSTRUCTIONS}\n\n"
        f"Log Data:\n{log_data}"
    )
    return {"role": "user", "content": full_prompt}
