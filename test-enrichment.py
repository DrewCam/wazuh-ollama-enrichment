#!/usr/bin/env python3
"""
Test script for the Ollama LLM alert enrichment integration.

Run directly to verify Ollama connectivity and end-to-end enrichment
quality without needing Wazuh to trigger it. Uses the same endpoint,
prompt, and JSON schema as the production custom-ollama-enrichment.py
script (/api/generate with think=false).

Usage:
    python3 test-enrichment.py [ollama_url] [model]

Example:
    python3 test-enrichment.py http://localhost:11434 qwen3.5:9b
    python3 test-enrichment.py http://localhost:11434 gemma4:e4b

Author: DrewCam
"""

import json
import sys
import time
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Constants — must match custom-ollama-enrichment.py exactly
# ---------------------------------------------------------------------------

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3.5:9b"
REQUEST_TIMEOUT_SECONDS = 300

ENRICHMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "severity_assessment": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        },
        "summary": {"type": "string"},
        "mitre_attack": {
            "type": "object",
            "properties": {
                "tactic": {"type": "string"},
                "tactic_id": {"type": "string"},
                "technique": {"type": "string"},
                "technique_id": {"type": "string"},
            },
            "required": ["tactic", "tactic_id", "technique", "technique_id"],
        },
        "investigation_steps": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "false_positive_likelihood": {
            "type": "string",
            "enum": ["HIGH", "MEDIUM", "LOW"],
        },
        "additional_context": {"type": "string"},
    },
    "required": [
        "severity_assessment", "summary", "mitre_attack",
        "investigation_steps", "recommended_actions",
        "confidence", "false_positive_likelihood", "additional_context",
    ],
}

SYSTEM_PROMPT = (
    "You are a senior SOC analyst assistant integrated with a Wazuh SIEM "
    "platform. Your role is to enrich security alerts with contextual "
    "analysis.\n\n"
    "You will receive a Wazuh alert in JSON format. Analyse it and provide "
    "enrichment.\n\n"
    "Rules:\n"
    "- Base your analysis ONLY on the alert data provided. Do not fabricate "
    "details.\n"
    "- If you are uncertain, set confidence to LOW and explain in "
    "additional_context.\n"
    "- Keep investigation_steps and recommended_actions practical and "
    "specific.\n"
    "- If Wazuh has already mapped a MITRE ATT&CK technique, validate and "
    "include it."
)

USER_PROMPT = "Analyse the following Wazuh alert and provide enrichment:\n\n"


# ---------------------------------------------------------------------------
# Sample Wazuh alerts covering each tested category
# ---------------------------------------------------------------------------

SAMPLE_ALERTS = [
    {
        "name": "SSH Brute Force (level 10)",
        "alert": {
            "id": "1774798886.12345",
            "timestamp": "2026-04-09T10:30:00.000+0000",
            "rule": {
                "id": "5763",
                "level": 10,
                "description": "sshd: brute force trying to get access "
                               "to the system. Non existent user.",
                "groups": ["syslog", "sshd", "authentication_failures"],
                "mitre": {
                    "tactic": ["Credential Access"],
                    "id": ["T1110"],
                    "technique": ["Brute Force"],
                },
                "frequency": 8,
                "timeframe": 120,
            },
            "agent": {
                "id": "001",
                "name": "PER-DCC-WKS-03",
                "ip": "192.168.86.48",
            },
            "manager": {"name": "PER-DCC-WAZUH"},
            "decoder": {"name": "sshd"},
            "location": "/var/log/auth.log",
            "data": {
                "srcip": "203.0.113.45",
                "srcport": "44322",
                "dstuser": "fakeuser",
            },
            "full_log": (
                "Apr  9 10:30:00 PER-DCC-WKS-03 sshd[12345]: "
                "Failed password for invalid user fakeuser from "
                "203.0.113.45 port 44322 ssh2"
            ),
        },
    },
    {
        "name": "Windows Account Created (level 8)",
        "alert": {
            "id": "1774798886.23456",
            "timestamp": "2026-04-09T11:15:00.000+0000",
            "rule": {
                "id": "60109",
                "level": 8,
                "description": "User account enabled or created",
                "groups": ["windows", "windows_security", "adduser",
                           "account_changed"],
                "mitre": {
                    "tactic": ["Persistence"],
                    "id": ["T1098"],
                    "technique": ["Account Manipulation"],
                },
            },
            "agent": {
                "id": "002",
                "name": "PER-DCC-WKS-01",
                "ip": "192.168.86.68",
            },
            "manager": {"name": "PER-DCC-WAZUH"},
            "decoder": {"name": "windows_eventchannel"},
            "location": "EventChannel",
            "data": {
                "win": {
                    "system": {
                        "eventID": "4720",
                        "computer": "PER-DCC-WKS-01",
                        "severityValue": "AUDIT_SUCCESS",
                    },
                    "eventdata": {
                        "targetUserName": "testattacker",
                        "targetDomainName": "PER-DCC-WKS-01",
                        "subjectUserName": "admin",
                        "subjectDomainName": "PER-DCC-WKS-01",
                        "subjectLogonId": "0xf0a5f0",
                        "samAccountName": "testattacker",
                        "primaryGroupId": "513",
                        "newUacValue": "0x15",
                        "userAccountControl": "%%2080 %%2082 %%2084",
                    },
                },
            },
            "full_log": (
                "Event 4720: A user account was created. "
                "Subject: admin. "
                "New Account: testattacker."
            ),
        },
    },
    {
        "name": "FIM: /etc/passwd Modified (level 7)",
        "alert": {
            "id": "1774798886.34567",
            "timestamp": "2026-04-09T12:00:00.000+0000",
            "rule": {
                "id": "550",
                "level": 7,
                "description": "Integrity checksum changed.",
                "groups": [
                    "ossec", "syscheck",
                    "syscheck_entry_modified", "syscheck_file",
                ],
                "mitre": {
                    "technique": ["Stored Data Manipulation"],
                    "id": ["T1565.001"],
                    "tactic": ["Impact"],
                },
            },
            "agent": {
                "id": "001",
                "name": "PER-DCC-WKS-03",
                "ip": "192.168.86.48",
            },
            "manager": {"name": "PER-DCC-WAZUH"},
            "decoder": {"name": "syscheck_integrity_changed"},
            "location": "syscheck",
            "syscheck": {
                "path": "/etc/passwd",
                "mode": "scheduled",
                "size_before": "2973",
                "size_after": "2974",
                "md5_before": "53ef0449f1a98ed7165ce97aff3712fb",
                "md5_after": "513314e17f46003d2db716f5a84108a2",
                "sha256_before": "b02f4dd949309c6e6df76a3370013766af13b08e",
                "sha256_after": "f0493409513774fe87d6438b8bc09df4ac155613",
                "changed_attributes": ["size", "mtime", "md5",
                                        "sha1", "sha256"],
                "event": "modified",
            },
            "full_log": (
                "File '/etc/passwd' modified\n"
                "Mode: scheduled\n"
                "Changed attributes: size,mtime,md5,sha1,sha256"
            ),
        },
    },
    {
        "name": "Sysmon: Process Injection (level 12)",
        "alert": {
            "id": "1774798886.45678",
            "timestamp": "2026-04-18T03:28:40.000+0000",
            "rule": {
                "id": "92910",
                "level": 12,
                "description": "Explorer process was accessed by "
                               "C:\\Users\\admin\\AppData\\Local\\"
                               "Microsoft\\OneDrive\\OneDrive.exe, "
                               "possible process injection",
                "groups": ["sysmon", "sysmon_eid10_detections", "windows"],
                "mitre": {
                    "technique": ["Process Injection"],
                    "id": ["T1055"],
                    "tactic": ["Defense Evasion", "Privilege Escalation"],
                },
            },
            "agent": {
                "id": "002",
                "name": "PER-DCC-WKS-01",
                "ip": "192.168.86.68",
            },
            "manager": {"name": "PER-DCC-WAZUH"},
            "decoder": {"name": "windows_eventchannel"},
            "location": "EventChannel",
            "data": {
                "win": {
                    "system": {
                        "providerName": "Microsoft-Windows-Sysmon",
                        "eventID": "10",
                        "computer": "PER-DCC-WKS-01",
                        "severityValue": "INFORMATION",
                    },
                    "eventdata": {
                        "sourceImage": "C:\\Users\\admin\\AppData\\Local\\"
                                       "Microsoft\\OneDrive\\OneDrive.exe",
                        "targetImage": "C:\\Windows\\explorer.exe",
                        "grantedAccess": "0x101411",
                        "callTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+"
                                     "9f4e4|C:\\Users\\admin\\AppData\\"
                                     "Local\\Microsoft\\OneDrive\\"
                                     "FileSyncClient.dll+2a1b3",
                        "sourceUser": "PER-DCC-WKS-01\\admin",
                    },
                },
            },
            "full_log": (
                "Process accessed: SourceImage: OneDrive.exe "
                "TargetImage: explorer.exe "
                "GrantedAccess: 0x101411"
            ),
        },
    },
]


# ---------------------------------------------------------------------------
# Ollama interaction
# ---------------------------------------------------------------------------

def query_ollama(ollama_url, model, alert):
    """Send alert to Ollama and return the response content, thinking
    trace, and performance statistics.

    Mirrors the production custom-ollama-enrichment.py configuration:
    /api/generate endpoint with think=false.
    """
    alert_json_string = json.dumps(alert, indent=2)

    payload = json.dumps({
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": USER_PROMPT + alert_json_string,
        "think": False,
        "stream": False,
        "format": ENRICHMENT_SCHEMA,
        "options": {"temperature": 0.1, "num_predict": 4096},
    }).encode("utf-8")

    api_url = f"{ollama_url.rstrip('/')}/api/generate"
    request = urllib.request.Request(
        api_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    response = urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS)
    response_body = response.read().decode("utf-8")
    response_json = json.loads(response_body)

    response_content = response_json.get("response", "")
    thinking_trace = response_json.get("thinking", "")

    # Fallback: if a model still emits to thinking, use that
    if not response_content.strip() and thinking_trace.strip():
        response_content, thinking_trace = thinking_trace, ""

    stats = {
        "eval_count": response_json.get("eval_count", 0),
        "eval_duration": response_json.get("eval_duration", 0),
        "prompt_eval_count": response_json.get("prompt_eval_count", 0),
        "total_duration": response_json.get("total_duration", 0),
        "load_duration": response_json.get("load_duration", 0),
    }

    return response_content, thinking_trace, stats


def parse_json_response(text):
    """Parse the LLM response as JSON, stripping markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[cleaned.index("\n") + 1:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return json.loads(cleaned.strip())


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_performance(elapsed_seconds, stats):
    """Print inference performance metrics."""
    tokens_generated = stats["eval_count"]
    eval_duration_ns = stats["eval_duration"]
    tokens_per_second = (
        tokens_generated / (eval_duration_ns / 1e9)
        if eval_duration_ns > 0 else 0
    )

    print(f"\n    PERFORMANCE")
    print(f"    Wall time:     {elapsed_seconds:.1f}s")
    print(f"    Tokens:        {tokens_generated} generated, "
          f"{stats['prompt_eval_count']} prompt")
    print(f"    Tokens/sec:    {tokens_per_second:.1f}")


def print_thinking_trace(thinking_trace):
    """Print a preview of the model's thinking trace if present."""
    if not thinking_trace:
        return
    PREVIEW_LENGTH = 400
    preview = thinking_trace[:PREVIEW_LENGTH]
    if len(thinking_trace) > PREVIEW_LENGTH:
        preview += f"\n    ... [{len(thinking_trace)} chars total]"
    print(f"\n    THINKING TRACE")
    for line in preview.split("\n"):
        print(f"    {line}")


def print_enrichment(enrichment):
    """Print the structured enrichment fields."""
    mitre = enrichment.get("mitre_attack", {})

    print(f"\n    ENRICHMENT")
    print(f"    Severity:    {enrichment.get('severity_assessment', '?')}")
    print(f"    Summary:     {enrichment.get('summary', 'N/A')}")
    print(f"    MITRE:       {mitre.get('technique', 'N/A')} "
          f"({mitre.get('technique_id', '?')}) / "
          f"{mitre.get('tactic', 'N/A')} ({mitre.get('tactic_id', '?')})")
    print(f"    Confidence:  {enrichment.get('confidence', '?')}")
    print(f"    FP risk:     "
          f"{enrichment.get('false_positive_likelihood', '?')}")

    investigation_steps = enrichment.get("investigation_steps", [])
    print(f"    Investigation ({len(investigation_steps)} steps):")
    for step_number, step in enumerate(investigation_steps, 1):
        print(f"      {step_number}. {step}")

    recommended_actions = enrichment.get("recommended_actions", [])
    print(f"    Actions ({len(recommended_actions)}):")
    for action_number, action in enumerate(recommended_actions, 1):
        print(f"      {action_number}. {action}")

    if enrichment.get("additional_context"):
        print(f"    Context:     {enrichment['additional_context']}")


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def test_connectivity(ollama_url, model):
    """Verify Ollama is reachable and the model is available."""
    print("\n[1] Testing Ollama connectivity...")
    try:
        tags_request = urllib.request.urlopen(
            f"{ollama_url}/api/tags", timeout=5
        )
        tags = json.loads(tags_request.read().decode("utf-8"))
        available_models = [m["name"] for m in tags.get("models", [])]
        print(f"    Connected. Models: {', '.join(available_models)}")
        if model not in available_models:
            print(f"    WARNING: {model} not in available models")
    except Exception as error:
        print(f"    FAILED: {error}")
        sys.exit(1)


def run_single_test(ollama_url, model, test_case, test_number, total_tests):
    """Run a single alert through the enrichment pipeline and display results."""
    alert = test_case["alert"]
    rule = alert["rule"]

    print(f"\n{'=' * 60}")
    print(f"[{test_number}/{total_tests}] {test_case['name']}")
    print(f"    Rule {rule['id']} (level {rule['level']}): "
          f"{rule['description']}")
    print("-" * 60)

    try:
        start_time = time.time()
        response_content, thinking_trace, stats = query_ollama(
            ollama_url, model, alert
        )
        elapsed_seconds = time.time() - start_time

        print_performance(elapsed_seconds, stats)
        print_thinking_trace(thinking_trace)

        enrichment = parse_json_response(response_content)
        print_enrichment(enrichment)
        print(f"\n    STATUS: PASS")

    except json.JSONDecodeError as error:
        print(f"    STATUS: FAIL (JSON parse error: {error})")
        if response_content:
            print(f"    Raw: {response_content[:300]}")
    except Exception as error:
        print(f"    STATUS: FAIL ({error})")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ollama_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OLLAMA_URL
    model = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL

    print(f"Ollama URL: {ollama_url}")
    print(f"Model:      {model}")
    print("=" * 60)

    test_connectivity(ollama_url, model)

    for test_number, test_case in enumerate(SAMPLE_ALERTS, 1):
        run_single_test(
            ollama_url, model, test_case, test_number, len(SAMPLE_ALERTS)
        )

    print(f"\n{'=' * 60}")
    print("All tests complete.")


if __name__ == "__main__":
    main()
