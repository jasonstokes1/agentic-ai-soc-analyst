# Agentic AI SOC Analyst & Threat Hunter 🛡️🤖

An enterprise-grade, autonomous security operations (SOC) assistant built with Python and Google Gemini models. This tool bridges the gap between natural language security inquiries and live telemetry, performing automated KQL translation, multi-model cost analysis, and resilient fault-tolerant threat hunting.

---

## 🚀 Key Architectural Highlights

* **Natural Language to KQL Translation:** Translates plain-English analyst queries into syntax-correct KQL (Kusto Query Language) targeting Microsoft Defender and Azure Log Analytics schemas (`DeviceProcessEvents`, `AzureNetworkAnalytics_CL`, etc.).
* **Production Cost & Token Guardrails:** Automatically calculates input token usage, rate limits (TPM), and cost estimates across multiple models before execution.
* **Resilient Multi-Model Fallback Cascade:** Automatically handles API rate limits (`429 RESOURCE_EXHAUSTED`) by cascading gracefully from high-tier models down to cost-effective alternatives without session disruption.
* **Cognitive Threat Hunting & MITRE ATT&CK Mapping:** Analyzes raw log output, extracts Indicators of Compromise (IOCs), maps behaviors to MITRE ATT&CK tactics/techniques, and outputs structured JSON findings.

---

## 📸 Project Showcase

### 1. Resilient Model Fallback & Cost Guardrails
*Demonstrating real-time telemetry processing (426 records), token cost calculation, and automated fallback handling on API quota limits.*

<img src="https://github.com/user-attachments/assets/17a08bec-31fb-46b3-ac9d-1bc9eea0e287" width="100%" />

### 2. Autonomous Threat Hunting & MITRE ATT&CK Output
*Showing the structured security finding, MITRE active-scanning technique mapping (`T1595.001`), indicator extraction, and automated incident logging.*

<img src="https://github.com/user-attachments/assets/eff9c05a-9688-4e0e-976a-e0733beb70a3" width="100%" />

---

## 🛠️ Tech Stack & Libraries
* **Python 3.14**
* **Google GenAI SDK** (`gemini-3.1-pro-preview`, `gemini-3.7-flash`, `gemini-3.5-flash-lite`)
* **Microsoft Azure Identity & Monitor SDKs** (Log Analytics KQL Execution)
* **Colorama** (Terminal UI formatting)

---

## ⚙️ Core Files
* `_main.py` — Core application loop and execution orchestrator.
* `EXECUTOR.py` — Handles Log Analytics workspace queries and Azure credential management.
* `MODEL_MANAGEMENT.py` — Manages model parameters, token counting, and cost estimations.
* `GUARDRAILS.py` — Implements safety validation and fault-tolerant fallback cascading.
* `PROMPT_MANAGEMENT.py` — Houses system prompts, MITRE guidelines, and KQL translation schemas.
