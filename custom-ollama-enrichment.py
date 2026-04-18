#!/usr/bin/env python3
"""
Wazuh Custom Integration: Ollama LLM Alert Enrichment
------------------------------------------------------
Receives high-severity alerts from the Wazuh Integrator module,
forwards the alert JSON to a local Ollama instance for contextual
analysis, and writes the enrichment back to the original alert
document in the Wazuh Indexer (OpenSearch).

Usage (called automatically by Wazuh integratord):
    custom-ollama-enrichment.py <alert_file> <api_key> <hook_url> [debug]

Arguments:
    alert_file  Path to the temporary JSON file containing the alert
    api_key     Value of <api_key> from ossec.conf. Carries the LLM
                model name in the form 'model:<name>' (e.g.
                'model:qwen3.5:9b'). Default if empty: qwen3.5:9b.
    hook_url    Value of <hook_url> from ossec.conf (Ollama API URL)
    debug       Set to 'debug' if integratord debug is enabled

Config split:
    Wazuh integration wiring (model, host, threshold) lives in the
    <integration> block in ossec.conf. Script runtime config (indexer
    credentials and TLS) lives in /var/ossec/etc/ollama-enrichment.conf
    so credentials stay out of ossec.conf.

Configuration file (/var/ossec/etc/ollama-enrichment.conf):
    indexer_url         Wazuh Indexer URL (default https://127.0.0.1:9200)
    indexer_user        Indexer username
    indexer_pass        Indexer password
    indexer_verify_tls  'true' (default) to verify the indexer certificate,
                        'false' to accept self-signed (required for the
                        default Wazuh OVA deployment).
    indexer_ca_path     Optional path to a CA bundle (PEM) to use when
                        verify_tls is true and the indexer presents a cert
                        signed by an internal CA.

Endpoint and thinking mode:
    Uses /api/generate (not /api/chat) with think=false. Endpoint
    benchmarking confirmed this combination is 3-6x faster for
    thinking-capable models while producing equivalent quality output.

Author: DrewCam
"""

import json
import sys
import ssl
import time
import base64
from datetime import datetime, timezone

try:
    import urllib.request
    import urllib.error
except ImportError:
    print("ERROR: urllib not available")
    sys.exit(1)


# ==========================================================================
#  Configuration constants
# ==========================================================================

DEFAULT_MODEL = "qwen3.5:9b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
REQUEST_TIMEOUT_SECONDS = 300
MAX_ALERT_CHARACTERS = 8000

# Wazuh Indexer (OpenSearch) defaults.
# Credentials and TLS options are loaded from
# /var/ossec/etc/ollama-enrichment.conf at startup. See load_config()
# below. These fallbacks are only used if the config file is absent
# or the corresponding key is missing.
INDEXER_URL = "https://127.0.0.1:9200"
INDEXER_USER = ""
INDEXER_PASS = ""
INDEXER_INDEX_PATTERN = "wazuh-alerts-*"

# TLS verification defaults to True (secure by default). The Wazuh
# OVA ships with self-signed certs and requires 'indexer_verify_tls=false'
# to be set explicitly in the config file. The deploy script writes
# this automatically for OVA deployments.
INDEXER_VERIFY_TLS = True
INDEXER_CA_PATH = None

CONFIG_FILE_PATH = "/var/ossec/etc/ollama-enrichment.conf"

# Log file paths (created by deploy-ollama-integration.sh)
ENRICHMENT_LOG_PATH = "/var/ossec/logs/ollama-enrichment.log"
DEBUG_LOG_PATH = "/var/ossec/logs/ollama-enrichment-debug.log"

# Delay before searching for the alert document in OpenSearch.
# Without this, the document is often not yet indexed when
# the enrichment tries to write back.
INDEXER_INITIAL_DELAY_SECONDS = 2
INDEXER_RETRY_DELAY_SECONDS = 5


def load_config():
    """Load configuration from the config file if it exists.

    Config file format (/var/ossec/etc/ollama-enrichment.conf):
        indexer_url=https://127.0.0.1:9200
        indexer_user=admin
        indexer_pass=admin
        indexer_verify_tls=false     # optional, default true
        indexer_ca_path=/etc/pki/ca.pem   # optional

    Lines starting with # are ignored. If the file does not exist,
    the script will fail to authenticate with the indexer - the config
    file is required for production use. The LLM model name is set in
    ossec.conf via <api_key>model:<name></api_key>, not here.
    """
    global INDEXER_URL, INDEXER_USER, INDEXER_PASS
    global INDEXER_VERIFY_TLS, INDEXER_CA_PATH

    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            for line in config_file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key == "indexer_url":
                    INDEXER_URL = value
                elif key == "indexer_user":
                    INDEXER_USER = value
                elif key == "indexer_pass":
                    INDEXER_PASS = value
                elif key == "indexer_verify_tls":
                    INDEXER_VERIFY_TLS = value.lower() in ("true", "yes", "1")
                elif key == "indexer_ca_path":
                    INDEXER_CA_PATH = value or None
    except FileNotFoundError:
        pass  # Config file absent; indexer writes will fail without credentials


# ==========================================================================
#  Prompt and structured output schema
# ==========================================================================

SYSTEM_PROMPT = """\
You are a senior SOC analyst assistant integrated with a Wazuh SIEM \
platform. Your role is to enrich security alerts with contextual analysis.

You will receive a Wazuh alert in JSON format. Analyse it and provide \
enrichment.

Rules:
- Base your analysis ONLY on the alert data provided. Do not fabricate details.
- If you are uncertain, set confidence to LOW and explain in additional_context.
- Keep investigation_steps and recommended_actions practical and specific.
- If Wazuh has already mapped a MITRE ATT&CK technique, validate and include it."""

USER_PROMPT = "Analyse the following Wazuh alert and provide enrichment:\n\n"

# Ollama validates LLM output against this schema via the "format" parameter,
# guaranteeing well-formed JSON with the expected fields.
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

REQUIRED_FIELDS = set(ENRICHMENT_SCHEMA["required"])


# ==========================================================================
#  Logging
# ==========================================================================

def write_debug_log(message, is_debug_enabled=False):
    """Append a timestamped debug message. Best-effort, never crashes."""
    if not is_debug_enabled:
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    try:
        with open(DEBUG_LOG_PATH, "a") as log_file:
            log_file.write(f"{timestamp} custom-ollama-enrichment: {message}\n")
    except Exception:
        pass


def write_audit_log(entry):
    """Append a JSON audit entry. One line per enrichment attempt."""
    try:
        with open(ENRICHMENT_LOG_PATH, "a") as log_file:
            log_file.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def build_audit_entry(status, alert_id, rule_id=None, rule_level=None,
                      model=None, tokens_generated=None, index=None,
                      doc_id=None, update_result=None, enrichment=None,
                      error=None):
    """Build a standardised audit log dictionary."""
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "status": status,
        "alert_id": alert_id,
    }

    # Only include fields that have values
    optional_fields = {
        "rule_id": rule_id,
        "rule_level": rule_level,
        "model": model,
        "tokens": tokens_generated,
        "index": index,
        "doc_id": doc_id,
        "update_result": update_result,
        "error": error,
    }
    for field_name, field_value in optional_fields.items():
        if field_value is not None:
            entry[field_name] = field_value

    if enrichment:
        entry["severity_assessment"] = enrichment.get("severity_assessment")
        entry["inference_time_seconds"] = enrichment.get("inference_time_seconds")

    return entry


# ==========================================================================
#  SSL context
# ==========================================================================

_cached_ssl_context = None


def get_ssl_context():
    """Reusable SSL context, configured via load_config().

    Behaviour is controlled by two config keys:
      - indexer_verify_tls (default: true) - verify the indexer cert
      - indexer_ca_path    (optional)      - path to a CA bundle (PEM)

    Secure by default. Set 'indexer_verify_tls=false' in the config
    file for self-signed deployments (e.g. the Wazuh OVA). Set
    'indexer_ca_path' to trust an internal CA without disabling
    verification.
    """
    global _cached_ssl_context
    if _cached_ssl_context is None:
        if INDEXER_VERIFY_TLS:
            _cached_ssl_context = ssl.create_default_context(
                cafile=INDEXER_CA_PATH
            )
        else:
            _cached_ssl_context = ssl.create_default_context()
            _cached_ssl_context.check_hostname = False
            _cached_ssl_context.verify_mode = ssl.CERT_NONE
    return _cached_ssl_context


# ==========================================================================
#  Ollama API
# ==========================================================================

def query_ollama(ollama_url, alert_json_string, model):
    """Send an alert to Ollama for enrichment via /api/generate.

    Returns a tuple of:
        (response_content, thinking_trace, tokens_generated,
         eval_duration_ns, prompt_token_count)
    """
    api_url = ollama_url.rstrip("/")
    if not api_url.endswith("/api/generate"):
        api_url += "/api/generate"

    payload = json.dumps({
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": USER_PROMPT + alert_json_string,
        "stream": False,
        "think": False,
        "format": ENRICHMENT_SCHEMA,
        "options": {"temperature": 0.1, "num_predict": 4096},
    }).encode("utf-8")

    request = urllib.request.Request(
        api_url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    response = urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS)
    result = json.loads(response.read().decode("utf-8"))

    response_content = result.get("response", "")
    thinking_trace = result.get("thinking", "")

    # Fallback: some models place output in thinking despite think=false
    if not response_content.strip() and thinking_trace.strip():
        response_content = thinking_trace
        thinking_trace = ""

    return (
        response_content,
        thinking_trace,
        result.get("eval_count", 0),
        result.get("eval_duration", 0),
        result.get("prompt_eval_count", 0),
    )


# ==========================================================================
#  Response parsing and normalisation
# ==========================================================================

def parse_json_response(text):
    """Parse JSON from LLM output, stripping markdown fences if present."""
    text = text.strip()
    if text.startswith("```"):
        text = text[text.index("\n") + 1:]
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())


def get_nested_value(data, *keys):
    """Safely traverse nested dicts. Returns None if any key is missing."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def normalise_enrichment(enrichment):
    """Ensure the enrichment has the expected schema.

    Most models follow the format schema correctly. For those that
    don't (returning alternative field names or nesting), this maps
    common variants to the expected structure.
    """
    if REQUIRED_FIELDS.issubset(enrichment.keys()):
        return enrichment

    normalised = {}

    normalised["severity_assessment"] = (
        enrichment.get("severity_assessment")
        or get_nested_value(enrichment, "analysis_summary", "severity")
        or "UNKNOWN"
    )
    normalised["summary"] = (
        enrichment.get("summary")
        or get_nested_value(enrichment, "analysis_summary", "description")
        or ""
    )

    # MITRE — try standard location, then threat_intelligence alternative
    mitre_data = enrichment.get("mitre_attack")
    if not isinstance(mitre_data, dict) or "technique_id" not in mitre_data:
        threat_intel = (
            get_nested_value(enrichment, "threat_intelligence",
                             "mitre_attack_validation") or {}
        )
        technique_string = threat_intel.get("technique", "")
        technique_id = ""
        technique_name = technique_string
        if "(" in technique_string and ")" in technique_string:
            technique_name = technique_string[:technique_string.index("(")].strip()
            technique_id = technique_string[
                technique_string.index("(") + 1:technique_string.index(")")
            ]
        mitre_data = {
            "tactic": threat_intel.get("tactic", ""),
            "tactic_id": "",
            "technique": technique_name,
            "technique_id": technique_id,
        }
    normalised["mitre_attack"] = mitre_data

    normalised["investigation_steps"] = (
        enrichment.get("investigation_steps") or []
    )
    normalised["recommended_actions"] = (
        enrichment.get("recommended_actions") or []
    )
    normalised["confidence"] = (
        enrichment.get("confidence")
        or get_nested_value(enrichment, "analysis_summary", "confidence")
        or "LOW"
    )
    normalised["false_positive_likelihood"] = (
        enrichment.get("false_positive_likelihood") or "MEDIUM"
    )
    normalised["additional_context"] = (
        enrichment.get("additional_context")
        or get_nested_value(enrichment, "contextual_enrichment",
                            "additional_context")
        or get_nested_value(enrichment, "contextual_enrichment",
                            "impact_assessment")
        or ""
    )

    return normalised


# ==========================================================================
#  Wazuh Indexer (OpenSearch)
# ==========================================================================

def indexer_request(method, path, body=None):
    """Authenticated HTTPS request to the Wazuh Indexer."""
    url = f"{INDEXER_URL}{path}"
    credentials = base64.b64encode(
        f"{INDEXER_USER}:{INDEXER_PASS}".encode()
    ).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }
    data = json.dumps(body).encode("utf-8") if body else None
    request = urllib.request.Request(
        url, data=data, headers=headers, method=method
    )
    response = urllib.request.urlopen(
        request, timeout=30, context=get_ssl_context()
    )
    return json.loads(response.read().decode("utf-8"))


def find_alert_document(alert_id):
    """Find the original alert document in OpenSearch.

    Returns (index_name, document_id) or (None, None) if not found.
    """
    result = indexer_request("POST", f"/{INDEXER_INDEX_PATTERN}/_search", {
        "query": {"bool": {"must": [{"match_phrase": {"id": alert_id}}]}},
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
    })
    hits = result.get("hits", {}).get("hits", [])
    if hits:
        return hits[0]["_index"], hits[0]["_id"]
    return None, None


def write_enrichment_to_alert(index_name, document_id, enrichment):
    """Write enrichment to the original alert under data.ai_enrichment."""
    result = indexer_request("POST", f"/{index_name}/_update/{document_id}", {
        "doc": {"data": {"ai_enrichment": enrichment}}
    })
    return result.get("result", "unknown")


def find_and_enrich_alert(alert_id, enrichment, is_debug_enabled):
    """Find the alert in OpenSearch and write the enrichment.

    Retries once after a delay if the document isn't indexed yet.
    Returns (index_name, document_id, update_result, status).
    """
    time.sleep(INDEXER_INITIAL_DELAY_SECONDS)
    index_name, document_id = find_alert_document(alert_id)

    if not index_name:
        write_debug_log("Not found, retrying...", is_debug_enabled)
        time.sleep(INDEXER_RETRY_DELAY_SECONDS)
        index_name, document_id = find_alert_document(alert_id)

    if not index_name:
        write_debug_log("Retry failed: document not found", is_debug_enabled)
        return None, None, None, "error_document_not_found"

    write_debug_log(f"Found: {index_name}/{document_id}", is_debug_enabled)
    update_result = write_enrichment_to_alert(index_name, document_id, enrichment)
    write_debug_log(f"Update: {update_result}", is_debug_enabled)
    return index_name, document_id, update_result, "success"


# ==========================================================================
#  Argument parsing
# ==========================================================================

def parse_integratord_arguments():
    """Parse the command-line arguments passed by Wazuh integratord.

    The LLM model is read from the <api_key> integration option as
    'model:<name>' (e.g. 'model:qwen3.5:9b'). If <api_key> is empty
    or missing the 'model:' prefix, DEFAULT_MODEL is used.

    Returns (alert_file_path, ollama_url, model, is_debug_enabled).
    """
    alert_file_path = sys.argv[1] if len(sys.argv) > 1 else None
    integration_options = sys.argv[2] if len(sys.argv) > 2 else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""
    is_debug_enabled = len(sys.argv) > 4 and sys.argv[4] == "debug"

    ollama_url = hook_url.strip() or DEFAULT_OLLAMA_URL

    model = DEFAULT_MODEL
    if integration_options:
        for option in integration_options.split(","):
            option = option.strip()
            if option.startswith("model:"):
                model = option.split(":", 1)[1]

    return alert_file_path, ollama_url, model, is_debug_enabled


# ==========================================================================
#  Enrichment pipeline steps
# ==========================================================================

def read_alert(alert_file_path):
    """Read and parse the alert JSON from the temporary file."""
    with open(alert_file_path, "r") as alert_file:
        return json.load(alert_file)


def prepare_alert_payload(alert):
    """Serialise the alert to JSON, truncating if too large."""
    alert_json_string = json.dumps(alert, indent=2)
    if len(alert_json_string) > MAX_ALERT_CHARACTERS:
        alert_json_string = (
            alert_json_string[:MAX_ALERT_CHARACTERS] + "\n... [truncated]"
        )
    return alert_json_string


def enrich_alert(ollama_url, alert_json_string, model):
    """Send the alert to Ollama and return the parsed enrichment with metadata."""
    start_time = time.time()
    response_content, thinking_trace, tokens_generated, eval_duration_ns, \
        prompt_token_count = query_ollama(ollama_url, alert_json_string, model)
    elapsed_seconds = time.time() - start_time

    enrichment = normalise_enrichment(parse_json_response(response_content))

    # Attach metadata
    enrichment["model_used"] = model
    enrichment["inference_time_seconds"] = round(elapsed_seconds, 1)
    enrichment["enriched_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    enrichment["thinking_trace"] = thinking_trace
    enrichment["tokens_generated"] = tokens_generated
    enrichment["prompt_tokens"] = prompt_token_count
    if eval_duration_ns > 0:
        enrichment["tokens_per_second"] = round(
            tokens_generated / (eval_duration_ns / 1e9), 1
        )

    return enrichment, tokens_generated


# ==========================================================================
#  Main
# ==========================================================================

def main():
    """Enrichment pipeline: read alert, query LLM, write back to OpenSearch."""
    load_config()

    alert_file_path, ollama_url, model, is_debug_enabled = (
        parse_integratord_arguments()
    )

    if not alert_file_path:
        sys.exit(1)

    write_debug_log(
        f"Started: model={model}, ollama_url={ollama_url}", is_debug_enabled
    )

    alert_id = "unknown"

    try:
        alert = read_alert(alert_file_path)
        alert_id = alert.get("id", "unknown")
        rule = alert.get("rule", {})
        write_debug_log(
            f"Alert: id={alert_id} rule={rule.get('id')} "
            f"level={rule.get('level')} desc={rule.get('description')}",
            is_debug_enabled,
        )

        alert_json_string = prepare_alert_payload(alert)
        write_debug_log(
            f"Sending to {ollama_url} using {model}", is_debug_enabled
        )

        enrichment, tokens_generated = enrich_alert(
            ollama_url, alert_json_string, model
        )
        write_debug_log(
            f"Severity: {enrichment.get('severity_assessment')}",
            is_debug_enabled,
        )

        index_name, document_id, update_result, status = find_and_enrich_alert(
            alert_id, enrichment, is_debug_enabled
        )

        write_audit_log(build_audit_entry(
            status, alert_id,
            rule_id=rule.get("id"),
            rule_level=rule.get("level"),
            model=model,
            enrichment=enrichment,
            tokens_generated=tokens_generated,
            index=index_name,
            doc_id=document_id,
            update_result=update_result,
            error="Alert not found in indexer" if not index_name else None,
        ))

    except json.JSONDecodeError as error:
        write_debug_log(f"JSON parse error: {error}", is_debug_enabled)
        write_audit_log(build_audit_entry(
            "error_json_parse", alert_id, error=str(error)
        ))

    except urllib.error.URLError as error:
        write_debug_log(f"Connection error: {error}", is_debug_enabled)
        write_audit_log(build_audit_entry(
            "error_connection", alert_id, error=str(error)
        ))

    except Exception as error:
        write_debug_log(f"Unexpected error: {error}", is_debug_enabled)
        write_audit_log(build_audit_entry(
            "error_unexpected", alert_id, error=str(error)
        ))


if __name__ == "__main__":
    main()
