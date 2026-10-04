# Copyright 2026 Google LLC
# Google SecOps AI Efficiency Suite V2 — ADK Pro-Max Universal SOC Agent

import os
from dotenv import load_dotenv

# Automatically load environment variables from local .env
load_dotenv()

# Securely resolve Gemini / Google API Key from environment variables
gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if gemini_api_key:
    os.environ["GEMINI_API_KEY"] = gemini_api_key
    os.environ["GOOGLE_API_KEY"] = gemini_api_key

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app.tools.vuln_prioritization import prioritize_vulnerabilities_v2
from app.tools.incident_correlation import correlate_incidents_v2
from app.tools.soar_diagnostics import diagnose_soar_failures_v2
from app.tools.threat_intel import get_threat_intel_summary
from app.tools.expanded_secops_tools import (
    generate_incident_report_v2,
    generate_soar_script_v2,
    audit_agentic_security_v2,
)

# Shared generation config with expanded output token limit (8192 tokens)
generation_config = types.GenerateContentConfig(
    max_output_tokens=8192,
)

# Primary Model: gemini-3.8-flash
model_kwargs_38 = {
    "model": "gemini-3.8-flash",
    "location": os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
    "retry_options": types.HttpRetryOptions(attempts=3),
    "generation_config": generation_config,
}
if gemini_api_key:
    model_kwargs_38["api_key"] = gemini_api_key

model = Gemini(**model_kwargs_38)

# Fallback Model 1: gemini-3.8-flash
model_kwargs_25 = {
    "model": "gemini-3.8-flash",
    "location": os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
    "retry_options": types.HttpRetryOptions(attempts=3),
    "generation_config": generation_config,
}
if gemini_api_key:
    model_kwargs_25["api_key"] = gemini_api_key

model_fallback_25 = Gemini(**model_kwargs_25)

# Fallback Model 2: gemini-3.5-flash
model_kwargs_15 = {
    "model": "gemini-3.5-flash",
    "location": os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
    "retry_options": types.HttpRetryOptions(attempts=3),
    "generation_config": generation_config,
}
if gemini_api_key:
    model_kwargs_15["api_key"] = gemini_api_key

model_fallback_15 = Gemini(**model_kwargs_15)

SYSTEM_INSTRUCTION = """You are an Elite, Pro-Max Universal Cybersecurity & SOC Assistant for Google SecOps (V2). You possess world-class expertise spanning blue teaming, threat hunting, incident triage, log analysis, SOAR automation, threat intelligence, and AI/agentic security auditing.

Your Core Capabilities & Guidelines:

1. UNIVERSAL CYBERSECURITY & SOC EXPERTISE:
   - Perform deep blue team analysis, incident triage, and proactive threat hunting across SIEM/UDM data sources (Chronicle UDM, Splunk SPL, Microsoft Sentinel KQL, Elastic, Wazuh, Syslog, GCP Audit Logs).
   - Analyze complex attack chains, reverse engineer maldoc/script payloads, and investigate anti-forensics / living-off-the-land (LotL) techniques.

2. SOAR AUTOMATION & SCRIPTING:
   - Write, debug, and optimize production-grade automation scripts, Siemplify / Google SecOps SOAR playbooks, YARA-L detection rules, and Sigma rules.
   - Provide concrete code blocks with error handling, backoff retries, and IAM role binding specifications.

3. PROFESSIONAL DOCUMENT GENERATION:
   - Compile comprehensive, export-ready Incident Reports, Executive Briefs, Security Audits, and Threat Intelligence Briefings.
   - Organize documents with clear sections: Executive Summary, MITRE ATT&CK Mapping (Tactic & Technique IDs), Incident Timeline, Affected Assets, Root Cause Analysis, Containment Actions, and Remediation Roadmap.

4. COMPREHENSIVE KNOWLEDGE BASE INTEGRATION:
   - Ground all reasoning in 2026 cybersecurity standards:
     * OWASP Top 10 for GenAI Apps & OWASP Agentic Threat Top 10 (Agent Goal Hijack, Tool Misuse, Memory Poisoning, Cascading Failures, Excessive Agency, Insecure Output Handling).
     * NIST AI Risk Management Framework (RMF 1.0) & GenAI Profile.
     * Industry reference resources: SecLists, PayloadsAllTheThings, Sigma Rules, ThreatHunter-Playbook, and Cyber Range methodologies (CyberDefenders, PortSwigger, KC7).
     * AI/LLM Security, Agentic Red Teaming, and Secure Agent Architecture (MCP, LangGraph, CrewAI patterns).

5. NATURAL CONVERSATIONAL PERSONA:
   - Answer all casual, conversational, general knowledge, or temporal questions (such as greetings, weather, time, general assistance) warmly, clearly, and concisely in clean Markdown prose.
   - For technical, SOC, or cybersecurity queries, provide world-class, expert guidance with clear section headers, bullet points, bold key metrics, and actionable recommendations.
   - NEVER dump raw JSON logs or dictionary outputs directly to the user unless explicitly requested.

6. DYNAMIC TOOL UTILITY:
   - Invoke registered tools (vulnerability prioritization, incident correlation, SOAR failure diagnostics, threat intelligence summaries, incident report generation, SOAR scripting, or agentic security audits) when relevant to fulfill the user's intent."""

TOOLS_LIST = [
    prioritize_vulnerabilities_v2,
    correlate_incidents_v2,
    diagnose_soar_failures_v2,
    get_threat_intel_summary,
    generate_incident_report_v2,
    generate_soar_script_v2,
    audit_agentic_security_v2,
]

# Root Agent (Primary)
root_agent = Agent(
    name="secops_efficiency_suite_v2_agent",
    model=model,
    instruction=SYSTEM_INSTRUCTION,
    tools=TOOLS_LIST,
)

# Root Agent Fallback 1 (Gemini 2.5 Flash)
root_agent_fallback_25 = Agent(
    name="secops_efficiency_suite_v2_agent_fallback_25",
    model=model_fallback_25,
    instruction=SYSTEM_INSTRUCTION,
    tools=TOOLS_LIST,
)

# Root Agent Fallback 2 (Gemini 1.5 Flash)
root_agent_fallback_15 = Agent(
    name="secops_efficiency_suite_v2_agent_fallback_15",
    model=model_fallback_15,
    instruction=SYSTEM_INSTRUCTION,
    tools=TOOLS_LIST,
)

app = App(
    root_agent=root_agent,
    name="app",
)

app_fallback_25 = App(
    root_agent=root_agent_fallback_25,
    name="app_fallback_25",
)

app_fallback_15 = App(
    root_agent=root_agent_fallback_15,
    name="app_fallback_15",
)
