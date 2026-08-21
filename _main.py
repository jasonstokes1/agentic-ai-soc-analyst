# Standard library
import time
import warnings
import logging

warnings.filterwarnings("ignore", category=UserWarning)
logging.getLogger("google_genai").setLevel(logging.ERROR)

# Third-party libraries
from colorama import Fore, init, Style
from google import genai
from azure.identity import InteractiveBrowserCredential
from azure.monitor.query import LogsQueryClient

# Local modules
import UTILITIES
import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS

# Initialize colorama
init(autoreset=True)

# Build the Log Analytics Client using Interactive Browser Login
credential = InteractiveBrowserCredential()
law_client = LogsQueryClient(credential=credential)

# Builds the Gemini client which is used to send requests to the Google API
gemini_client = genai.Client(api_key=_keys.GOOGLE_API_KEY)

# Assign the default model to be used.
model = MODEL_MANAGEMENT.DEFAULT_MODEL

print(f"{Fore.LIGHTGREEN_EX}=== Agentic SOC Analyst Online ===")
print(f"{Fore.WHITE}Type 'exit' or 'quit' at any time to end the session.\n")

while True:
    # Get the message from the user (What do you want to hunt for?)
    user_message = PROMPT_MANAGEMENT.get_user_message() 

    # Check for exit command
    if user_message["content"].lower() in {"exit", "quit"}:
        print(f"{Fore.CYAN}Exiting Agentic SOC Analyst. Stay safe out there!{Fore.RESET}")
        break

    if not user_message["content"]:
        continue

    # return an object that describes the user's request as well as where and how the agent has decided to search
    unformatted_query_context = EXECUTOR.get_query_context(gemini_client, user_message, model=model)
    
    if not unformatted_query_context:
        print(f"{Fore.RED}Failed to determine query context. Please try phrasing your request differently.{Fore.RESET}")
        continue

    # sanitizing unformatted_query_context values, and normalizing field formats.
    query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

    # Show the user where we are going to search based on their request
    UTILITIES.display_query_context(query_context)

    # Ensure the table and fields returned by the model are allowed to be queried
    GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])

    # Query Log Analytics Workspace
    law_query_results = EXECUTOR.query_log_analytics(
        log_analytics_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        timerange_hours=query_context["time_range_hours"],
        table_name=query_context["table_name"],
        device_name=query_context["device_name"],
        fields=query_context["fields"],
        caller=query_context["caller"],
        user_principal_name=query_context["user_principal_name"],
        limit=query_context.get("limit"))

    number_of_records = law_query_results['count']

    print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

    # If no records are returned, loop back to prompt instead of exiting
    if number_of_records == 0:
        print(f"{Fore.YELLOW}No records found for this query. Moving to next prompt.\n{Fore.RESET}")
        continue

    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=user_message["content"],
        table_name=query_context["table_name"],
        log_data=law_query_results["records"]
    )

    # Grab the threat hunt system prompt
    threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT

    # Place the system and user prompts in an array
    threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

    # Count / estimate total input tokens
    number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model)

    # Observe rate limits, estimated cost, and select a model for analysis
    model = MODEL_MANAGEMENT.choose_model(model, number_of_tokens)

    # Ensure the selected model is allowed / valid
    GUARDRAILS.validate_model(model)
    print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...\n")

    # Grab the time the analysis started for calculating analysis duration
    start_time = time.time()

    # Execute the threat hunt 
    hunt_results = EXECUTOR.hunt(
        gemini_client=gemini_client,
        threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
        threat_hunt_user_message=threat_hunt_user_message,
        gemini_model=model
    )

    if not hunt_results:
        print(f"{Fore.RED}Threat hunt execution returned no results.{Fore.RESET}")
        continue

    # Grab the time the analysis finished and calculated the total time elapsed
    elapsed = time.time() - start_time

    # Notify the user of hunt analysis duration and findings
    print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results.get('findings', []))} {Fore.WHITE}potential threat(s)!\n")

    # Pause before displaying the results
    input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results.")

    # Display the threat hunt analysis results.
    UTILITIES.display_threats(threat_list=hunt_results.get('findings', []))

    # Containment decision: gather all high-confidence findings for this host and
    # ask the analyst ONCE, so the isolation call is made with the full picture
    # rather than after each individual finding.
    query_is_about_individual_host = query_context["about_individual_host"]
    findings = hunt_results.get('findings', [])

    if query_is_about_individual_host:
        high_confidence = [
            t for t in findings
            if t.get("confidence", "").lower() == "high"
        ]

        if high_confidence:
            device = query_context["device_name"]
            print(Fore.YELLOW + f"\n[!] {len(high_confidence)} high confidence threat(s) detected on host:" + Style.RESET_ALL, device)
            for t in high_confidence:
                print(Fore.LIGHTRED_EX + f"    - {t.get('title')}" + Style.RESET_ALL)

            confirm = input(
                f"\n{Fore.RED}{Style.BRIGHT}Isolate {device} from the network? (yes/no): " + Style.RESET_ALL
            ).strip().lower()

            if confirm.startswith("y"):
                try:
                    token = EXECUTOR.get_bearer_token()
                    machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                        token=token,
                        device_name=device
                    )
                    if EXECUTOR.quarantine_virtual_machine(token=token, machine_id=machine_id):
                        print(Fore.GREEN + "[+] VM successfully isolated." + Style.RESET_ALL)
                        print(Fore.CYAN + "Reminder: Release the VM from isolation when appropriate at: " + Style.RESET_ALL + "https://security.microsoft.com/")
                    else:
                        print(Fore.RED + "[!] Isolation request was not accepted by Defender." + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"[!] Containment unavailable: {str(e)[:120]}" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + "[i] Isolation skipped by analyst." + Style.RESET_ALL)

    print(f"\n{Fore.GREEN}Ready for your next threat hunting query!{Fore.RESET}\n")
