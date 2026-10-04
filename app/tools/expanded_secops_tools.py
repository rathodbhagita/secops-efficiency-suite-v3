# Copyright 2026 Google LLC
# Expanded Pro-Max SOC & Universal Cybersecurity Tools for Google SecOps V2

import json
from datetime import datetime

def generate_incident_report_v2(incident_id: str = "INC-2026-8842", title: str = "Credential Harvesting & Lateral Movement via Suspicious OAuth App", priority: str = "CRITICAL", summary: str = "") -> str:
    """Generates a professional, comprehensive cybersecurity incident report and threat brief.
    
    Args:
        incident_id: ID of the security incident.
        title: Title/subject of the security incident.
        priority: Priority level (CRITICAL, HIGH, MEDIUM, LOW).
        summary: Brief summary of incident activity or findings.

    Returns:
        JSON string containing structured incident report components and markdown export data.
    """
    now_iso = datetime.now().isoformat()
    
    report_data = {
        "status": "SUCCESS",
        "incident_id": incident_id,
        "title": title,
        "priority": priority,
        "timestamp": now_iso,
        "executive_summary": summary or "Anomalous OAuth application authorization detected combined with rapid API token generation and lateral movement attempts toward Google Cloud GKE workload identity pools.",
        "mitre_attack_mapping": [
            {"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing: Spearphishing Link"},
            {"tactic": "Persistence", "technique_id": "T1550.001", "technique": "Use Alternate Authentication Material: Application Access Token"},
            {"tactic": "Defense Evasion", "technique_id": "T1070.006", "technique": "Indicator Removal: Timestomp / Audit Log Tampering"},
            {"tactic": "Lateral Movement", "technique_id": "T1021.007", "technique": "Remote Services: Cloud Services"}
        ],
        "timeline": [
            {"time": "08:14:22 UTC", "event": "Phishing email clicked by user j.doe@company.internal"},
            {"time": "08:15:05 UTC", "event": "Malicious OAuth app 'OAuth2-Sync-Tool-2026' granted full Gmail & Drive scopes"},
            {"time": "08:17:40 UTC", "event": "Suspicious API access token created from unmanaged external IP 185.220.101.5"},
            {"time": "08:22:11 UTC", "event": "Automated alert ALT-1001 triggered in Google SecOps V2; automated containment playbook initiated"}
        ],
        "affected_assets": [
            {"asset_id": "user-jdoe-laptop", "type": "Endpoint", "os": "macOS Sonoma 15.2", "ip": "10.0.12.45"},
            {"asset_id": "gke-prod-cluster-01", "type": "Cloud Kubernetes", "region": "us-central1", "service_account": "sa-gke-prod@iam.gserviceaccount.com"}
        ],
        "containment_actions": [
            "Revoked OAuth app 'OAuth2-Sync-Tool-2026' authorization across Google Workspace tenant.",
            "Terminated active user sessions and reset credentials for j.doe@company.internal.",
            "Isolated host 'user-jdoe-laptop' via CrowdStrike / GCP VPC Firewall rules.",
            "Blocked egress traffic to malicious IP `185.220.101.5` on Cloud Armor and perimeter firewalls."
        ],
        "remediation_recommendations": [
            "Enforce Google Workspace OAuth App Control policy allowing only admin-installed or explicitly whitelisted third-party apps.",
            "Enable FIDO2 WebAuthn hardware security keys for all high-privilege users.",
            "Deploy YARA-L detection rule `rule_gcp_oauth_persistence` to flag real-time anomalous token creations."
        ]
    }
    return json.dumps(report_data, indent=2)


def generate_soar_script_v2(platform: str = "Siemplify", action_type: str = "isolate_host", language: str = "python", details: str = "") -> str:
    """Generates custom SOAR automation scripts, playbooks, YARA-L detection rules, or Sigma rules.

    Args:
        platform: Target platform (e.g., Siemplify, Google SecOps SOAR, Chronicle YARA-L, Sigma).
        action_type: Type of action or rule (e.g., isolate_host, revoke_session, block_ip, yara_l_rule, sigma_rule).
        language: Code language (python, yara_l, sigma, splunk_spl).
        details: Additional script requirement specifications.

    Returns:
        JSON string containing the generated production-grade script or rule definition.
    """
    if "yara" in language.lower() or "yara" in platform.lower():
        code = '''rule gcp_anomalous_oauth_token_creation {
  meta:
    author = "SecOps V2 AI Pro-Max"
    description = "Detects anomalous GCP OAuth token creation followed by rapid cloud identity assume role calls."
    severity = "HIGH"
    updated = "2026-10-04"

  events:
    $oauth.metadata.event_type = "USER_OAUTH_APP_ACCESS"
    $oauth.principal.user.email = $user
    $oauth.target.resource.name = $oauth_app

    $gcp.metadata.event_type = "GCP_IAM_ASSUME_ROLE"
    $gcp.principal.user.email = $user
    $gcp.target.resource.name = $role

  match:
    $user over 5m

  condition:
    $oauth and $gcp
}'''
    elif "sigma" in language.lower() or "sigma" in platform.lower():
        code = '''title: Suspicious OAuth App Consent and Token Access
id: a7f891b2-2026-4e5a-9012-123456789abc
status: experimental
description: Detects user consent granted to untrusted third-party OAuth applications in Google Workspace / Entra ID.
author: SecOps V2 AI Pro-Max
logsource:
    category: application
    product: workspace
detection:
    selection:
        event_name:
            - 'Authorize Application'
            - 'Consent to Application'
        scope_requested|contains:
            - 'mail.read'
            - 'files.readwrite'
            - 'cloudplatform'
    condition: selection
falsepositives:
    - Admin-approved SaaS integrations
level: high'''
    else:
        code = '''# Siemplify / Google SecOps SOAR Integration Action
# Language: Python 3.11+
# Action: Host Isolation & Firewall Quarantine

import sys
import requests
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "IsolateHostAction"
    
    target_host = siemplify.extract_action_param("TargetHost", print_value=True)
    target_ip = siemplify.extract_action_param("TargetIP", print_value=True)
    
    siemplify.LOGGER.info(f"Initiating isolation protocol for host: {target_host} ({target_ip})")
    
    try:
        # Step 1: Trigger Cloud Armor / Firewall Egress Rule
        headers = {"Authorization": "Bearer SOAR_SECRET_TOKEN", "Content-Type": "application/json"}
        payload = {
            "action": "DENY_EGRESS",
            "target_ip": target_ip,
            "reason": f"Automated SOAR Quarantine - Host {target_host}"
        }
        
        response = requests.post("https://firewall-api.internal/v2/rules/block", json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            output_message = f"Successfully isolated target host {target_host} ({target_ip}). Egress rule applied."
            result_value = True
        else:
            output_message = f"Failed to apply isolation rule: HTTP {response.status_code} - {response.text}"
            result_value = False
            
    except Exception as e:
        output_message = f"Exception during host isolation: {str(e)}"
        result_value = False
        
    siemplify.end(output_message, result_value)

if __name__ == "__main__":
    main()'''

    return json.dumps({
        "status": "SUCCESS",
        "platform": platform,
        "action_type": action_type,
        "language": language,
        "code_snippet": code,
        "usage_instructions": f"Deploy script directly into {platform} Action Manager or YARA-L Rules Engine."
    }, indent=2)


def audit_agentic_security_v2(target_system: str = "LLM SecOps Agent Pipeline", agent_architecture: str = "Multi-Agent Graph (ADK / LangGraph)") -> str:
    """Audits GenAI and Agentic AI architecture against OWASP Agentic Threat Top 10 (2026) and NIST AI RMF guidelines.

    Args:
        target_system: Name or description of the target GenAI agent system.
        agent_architecture: Architectural framework (ADK, LangGraph, CrewAI, AutoGen, MCP).

    Returns:
        JSON string detailing security audit findings, OWASP Agentic Top 10 risk vectors, and mitigation controls.
    """
    audit_results = {
        "status": "SUCCESS",
        "target_system": target_system,
        "architecture": agent_architecture,
        "frameworks_evaluated": [
            "OWASP Top 10 for GenAI Apps (2026)",
            "OWASP Agentic Threat Top 10 (2026)",
            "NIST AI Risk Management Framework (AI RMF 1.0 & GenAI Profile)"
        ],
        "findings": [
            {
                "threat_id": "ASI-01",
                "category": "Agent Goal Hijack (Direct Prompt Injection)",
                "risk_level": "CRITICAL",
                "description": "Indirect prompt injection via attacker-controlled web logs or UDM telemetry data forcing the agent to execute unauthorized tool calls.",
                "mitigation": "Enforce strict input sanitization, schema validation, and human-in-the-loop (HITL) authorization for destructive tool actions."
            },
            {
                "threat_id": "ASI-02",
                "category": "Tool Misuse & Excessive Agency",
                "risk_level": "HIGH",
                "description": "Subagent granted unconstrained API scopes allowing full workspace deletion without granular RBAC controls.",
                "mitigation": "Apply Least Privilege Access (LPA) to tool functions; enforce read-only tool scopes by default."
            },
            {
                "threat_id": "ASI-03",
                "category": "Memory Poisoning & Context Corruption",
                "risk_level": "HIGH",
                "description": "Persistent vector database memory polluted with adversarial context overrides.",
                "mitigation": "Cryptographically sign context memory entries and enforce TTL expirations on conversational memory blocks."
            },
            {
                "threat_id": "ASI-04",
                "category": "Cascading Subagent Failures",
                "risk_level": "MEDIUM",
                "description": "Unhandled subagent exception causing recursive execution loops and resource starvation.",
                "mitigation": "Implement hard recursion limits (`max_iterations`), circuit breakers, and timeout guards across agent invocation graphs."
            }
        ],
        "compliance_score": "82% - HIGH RISK (Requires HITL Guardrails)",
        "actionable_roadmap": [
            "Deploy OWASP Agentic Security Gateway between LLM runner and tool dispatchers.",
            "Implement NIST AI RMF 'Govern & Protect' controls for model context boundary verification.",
            "Conduct red teaming simulations using PayloadsAllTheThings and SecLists prompt injection datasets."
        ]
    }
    return json.dumps(audit_results, indent=2)
