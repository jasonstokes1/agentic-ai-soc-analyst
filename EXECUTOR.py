# Standard library
from datetime import timedelta
import json
import re
import time
import urllib.parse

# Third-party libraries
import pandas as pd
import requests
from colorama import Fore, Style
from azure.identity import DefaultAzureCredential
from google.genai import types
from google.genai.errors import APIError

# Local modules
import PROMPT_MANAGEMENT

# Sentinel values a model may emit when it means "no filter / everything".
# TOOL_DEF marks device_name, caller, and user_principal_name as required, so the
# model must supply *something* even for tenant-wide hunts. KQL startswith is a
# literal prefix match, so filtering on these would silently return zero rows.
# Hard ceiling on rows sent to the model. A tenant-wide hunt can match tens of
# thousands of events, which blows past both the context window and the API quota.
MAX_RECORDS = 500

UNSCOPED_VALUES = {"", "*", "all", "any", "none", "n/a", "null", "none specified", "unspecified"}


def is_unscoped(value):
    """True when a filter value means 'no filter' rather than a real identifier."""
    return str(value).strip().lower() in UNSCOPED_VALUES


def _escape_bad_backslashes(text):
    """Double any backslash that does not begin a valid JSON escape sequence."""
    valid = set('"\\/bfnrtu')
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt in valid:
                out.append(c)
                out.append(nxt)
                i += 2
                continue
            out.append("\\\\")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token

def get_mde_workstation_id_from_name(token, device_name):
    headers = {"Authorization": f"Bearer {token.token}"}
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No machine found starting with {device_name}")
    return machines[0]["id"]

def quarantine_virtual_machine(token, machine_id):
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }
    payload = {
        "Comment": "Isolation via Python Agentic AI",
        "IsolationType": "Full"
    }
    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )
    if resp.status_code in [200, 201]:
        return True
    return False

def hunt(gemini_client, threat_hunt_system_message, threat_hunt_user_message, gemini_model):
    # Automated Fallback Chain: 3.1-pro-preview -> 3.7-flash -> 3.5-flash-lite
    model_fallback_chain = ["gemini-3.1-pro-preview", "gemini-3.7-flash", "gemini-3.5-flash-lite"]

    if gemini_model in model_fallback_chain:
        model_fallback_chain.remove(gemini_model)
        model_fallback_chain.insert(0, gemini_model)

    for current_model in model_fallback_chain:
        try:
            print(f"{Fore.CYAN}Attempting cognitive hunt using model: {current_model}...{Style.RESET_ALL}")
            response = gemini_client.models.generate_content(
                model=current_model,
                contents=threat_hunt_user_message["content"],
                config=types.GenerateContentConfig(
                    system_instruction=threat_hunt_system_message["content"],
                    response_mime_type="application/json",
                    temperature=0.2
                )
            )
            print(f"{Fore.GREEN}Successfully completed hunt with {current_model}!{Style.RESET_ALL}")
            try:
                return json.loads(response.text)
            except json.JSONDecodeError:
                # Models sometimes emit Windows paths with unescaped backslashes,
                # which are invalid JSON escapes. Repair and retry once.
                repaired = _escape_bad_backslashes(response.text)
                print(f"{Fore.LIGHTYELLOW_EX}Malformed JSON from {current_model}; attempting repair...{Style.RESET_ALL}")
                return json.loads(repaired)
        except APIError as e:
            if "503" in str(e) or "UNAVAILABLE" in str(e) or "404" in str(e):
                print(f"{Fore.LIGHTYELLOW_EX}Model {current_model} unavailable or error encountered. Falling back to next model...{Style.RESET_ALL}")
                continue
            else:
                print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}Model {current_model} unavailable: {str(e)[:90]}...{Style.RESET_ALL}")
                continue
        except Exception as e:
            print(f"{Fore.RED}Unexpected error with {current_model}: {str(e)[:90]}...{Style.RESET_ALL}")
            continue

    print(f"{Fore.RED}{Style.BRIGHT}All models in the fallback chain failed.{Style.RESET_ALL}")
    return None

def get_query_context(gemini_client, user_message, model):
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n{Style.RESET_ALL}")

    # Fallback chain for tool selection as well
    tool_models = ["gemini-3.1-pro-preview", "gemini-3.7-flash", "gemini-3.5-flash-lite"]

    for cur_model in tool_models:
        try:
            response = gemini_client.models.generate_content(
                model=cur_model,
                contents=user_message["content"],
                config=types.GenerateContentConfig(
                    system_instruction=PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION["content"],
                    tools=[PROMPT_MANAGEMENT.TOOL_DEF],
                    temperature=0.1
                )
            )
            if response.function_calls:
                function_call = response.function_calls[0]
                args = function_call.args
                if isinstance(args, str):
                    args = json.loads(args)
                return dict(args)
        except Exception:
            continue

    print(f"{Fore.RED}Model did not return a tool call across available models.{Style.RESET_ALL}")
    return None

def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name, limit=None):
    field_str = ", ".join(fields) if isinstance(fields, list) else fields

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}\n| where FlowType_s == "MaliciousFlow"\n| project {field_str}'''

    elif table_name == "AzureActivity":
        user_query = f'''{table_name}\n| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")'''
        if not is_unscoped(caller):
            user_query += f'''\n| where Caller startswith "{caller}"'''
        user_query += f'''\n| project {field_str}'''

    elif table_name == "SigninLogs":
        if is_unscoped(user_principal_name):
            user_query = f'''{table_name}\n| project {field_str}'''
        else:
            user_query = f'''{table_name}\n| where UserPrincipalName startswith "{user_principal_name}"\n| project {field_str}'''

    else:
        if is_unscoped(device_name):
            user_query = f'''{table_name}\n| project {field_str}'''
        else:
            user_query = f'''{table_name}\n| where DeviceName startswith "{device_name}"\n| project {field_str}'''

    try:
        row_cap = int(limit) if limit else MAX_RECORDS
    except (TypeError, ValueError):
        row_cap = MAX_RECORDS
    row_cap = max(1, min(row_cap, MAX_RECORDS))
    user_query += f"\n| take {row_cap}"

    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")
    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }

    table = response.tables[0]
    record_count = len(table.rows)
    columns = table.columns
    rows = table.rows
    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)
    return { "records": records, "count": record_count }
