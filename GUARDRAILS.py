from colorama import Fore, Style

ALLOWED_TABLES = {
    "DeviceProcessEvents": True,
    "DeviceNetworkEvents": True,
    "DeviceLogonEvents": True,
    "AlertInfo": True,
    "AlertEvidence": True,
    "DeviceFileEvents": True,
    "DeviceRegistryEvents": True,
    "AzureNetworkAnalytics_CL": True,
    "AzureActivity": True,
    "SigninLogs": True,
}

ALLOWED_MODELS = {
    "gemini-3.1-pro-preview": {"max_input_tokens": 2_000_000, "max_output_tokens": 8192, "cost_per_million_input": 1.25, "cost_per_million_output": 5.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gemini-3.7-flash":       {"max_input_tokens": 1_000_000, "max_output_tokens": 8192, "cost_per_million_input": 0.075, "cost_per_million_output": 0.30,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gemini-3.5-flash-lite":  {"max_input_tokens": 1_000_000, "max_output_tokens": 8192, "cost_per_million_input": 0.0375, "cost_per_million_output": 0.15, "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}}
}

def validate_tables_and_fields(table, fields):
    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Table '{table}' is not allowed — exiting.{Style.RESET_ALL}")
        exit(1)
    print(f"{Fore.WHITE}Table and fields validated successfully (Dynamic Mode).\n")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — exiting.{Style.RESET_ALL}")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")
