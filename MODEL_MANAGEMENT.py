from colorama import Fore, Style
import GUARDRAILS

CURRENT_TIER = "4" 
DEFAULT_MODEL = "gemini-3.1-pro-preview"
WARNING_RATIO = 0.80

def money(usd):
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"

def color_for_usage(used, limit):
    if limit is None:
        return Fore.LIGHTGREEN_EX
    if used > limit:
        return Fore.LIGHTRED_EX
    if used >= WARNING_RATIO * limit:
        return Fore.LIGHTYELLOW_EX
    return Fore.LIGHTGREEN_EX

def colorize(label, used, limit):
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"

def estimate_cost(input_tokens, output_tokens, model_info):
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout

def print_model_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    print(f"Model limits and estimated total cost:{Fore.WHITE}\n")
    for name, info in GUARDRAILS.ALLOWED_MODELS.items():
        tpm_limit = info["tier"].get(tier)
        usage_text = colorize("input limit", input_tokens, info["max_input_tokens"])
        tpm_text = colorize("rate_limit", input_tokens, tpm_limit)
        est = estimate_cost(input_tokens, assumed_output_tokens, info)
        tag = f"{Fore.CYAN} <-- (current){Fore.WHITE}" if name == current_model else ""
        print(f"{name:<26} | {usage_text:<35} | {tpm_text:<32} | out_max: {info['max_output_tokens']:<6} | est_cost: {money(est)}{tag}")
    print("")

def assess_limits(model_name, input_tokens, tier):
    info = GUARDRAILS.ALLOWED_MODELS[model_name]
    msgs = []
    usage_txt = colorize("input limit", input_tokens, info["max_input_tokens"])
    if input_tokens > info["max_input_tokens"]:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds the input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * info["max_input_tokens"]:
        msgs.append(f"⚠️ WARNING: {usage_txt} is at least 80% of the input limit for {model_name}.")
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within the input limit for {model_name}.")

    tpm_limit = info["tier"].get(tier)
    tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
    if tpm_limit is not None:
        if input_tokens > tpm_limit:
            msgs.append(f"⚠️ WARNING: {tpm_txt} exceeds the TPM rate limit for {model_name} ({tpm_limit}) — may be too large.")
        elif input_tokens >= WARNING_RATIO * tpm_limit:
            msgs.append(f"⚠️ WARNING: {tpm_txt} is at least 80% of the TPM rate limit for {model_name}.")
        else:
            msgs.append(f"✅ Safe: {tpm_txt} is within the TPM rate limit for {model_name}.")
    else:
        msgs.append(f"ℹ️ No TPM tier limit known for {model_name} at tier '{tier}'.")

    print("\n".join(msgs))
    print("")

def choose_model(model_name, input_tokens, tier=CURRENT_TIER, assumed_output_tokens=500, interactive=False):
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        model_name = DEFAULT_MODEL
    print_model_table(input_tokens, model_name, tier, assumed_output_tokens)
    assess_limits(model_name, input_tokens, tier)
    return model_name

def count_tokens(messages, model):
    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(text) // 4
