#!/bin/bash
# ==========================================================================
# deploy-ollama-integration.sh
# Deploys the Ollama LLM alert enrichment integration to Wazuh.
#
# What it does:
#   1. Copies the integration scripts to /var/ossec/integrations/
#   2. Creates audit and debug log files with correct permissions
#   3. Creates a config file for indexer credentials
#   4. Optionally inserts the integration block into ossec.conf
#   5. Tests connectivity to both Ollama and the Wazuh Indexer
#
# Usage:
#   sudo bash deploy-ollama-integration.sh [ollama_url]
#
# Manual deployment (without this script):
#   1. Copy the integration scripts to the Wazuh integrations directory:
#        cp custom-ollama-enrichment    /var/ossec/integrations/
#        cp custom-ollama-enrichment.py /var/ossec/integrations/
#
#   2. Set ownership and permissions (Wazuh requires root:wazuh, 750):
#        chmod 750  /var/ossec/integrations/custom-ollama-enrichment
#        chmod 750  /var/ossec/integrations/custom-ollama-enrichment.py
#        chown root:wazuh /var/ossec/integrations/custom-ollama-enrichment
#        chown root:wazuh /var/ossec/integrations/custom-ollama-enrichment.py
#
#   3. Create log files with correct permissions:
#        touch /var/ossec/logs/ollama-enrichment.log
#        touch /var/ossec/logs/ollama-enrichment-debug.log
#        chown wazuh:wazuh /var/ossec/logs/ollama-enrichment.log
#        chown wazuh:wazuh /var/ossec/logs/ollama-enrichment-debug.log
#        chmod 660 /var/ossec/logs/ollama-enrichment.log
#        chmod 660 /var/ossec/logs/ollama-enrichment-debug.log
#
#   4. Create the runtime config file (indexer credentials + TLS).
#      Wazuh integration wiring (URL, model, threshold) lives in
#      ossec.conf, not here:
#        cat > /var/ossec/etc/ollama-enrichment.conf <<EOF
#        indexer_url=https://127.0.0.1:9200
#        indexer_user=admin
#        indexer_pass=admin
#        indexer_verify_tls=false   # 'true' in production, 'false' for Wazuh OVA self-signed
#        #indexer_ca_path=/path/to/ca.pem
#        EOF
#        chown root:wazuh /var/ossec/etc/ollama-enrichment.conf
#        chmod 640 /var/ossec/etc/ollama-enrichment.conf
#      This keeps credentials out of ossec.conf. If this file is
#      absent, the script will be unable to authenticate with the
#      indexer.
#
#   5. Add the integration block to /var/ossec/etc/ossec.conf
#      (inside the <ossec_config> tags):
#        <integration>
#          <name>custom-ollama-enrichment</name>
#          <hook_url>http://<OLLAMA_HOST_IP>:11434</hook_url>
#          <api_key>model:qwen3.5:9b</api_key>
#          <level>10</level>
#          <alert_format>json</alert_format>
#        </integration>
#      The <api_key> field carries the LLM model. Format: model:<name>.
#      If the <api_key> line is omitted or the 'model:' prefix missing,
#      the script defaults to qwen3.5:9b.
#
#   6. (Optional) Enable debug logging:
#        echo "integrator.debug=2" >> /var/ossec/etc/local_internal_options.conf
#
#   7. Restart the Wazuh manager:
#        systemctl restart wazuh-manager
#
# Author: DrewCam
# ==========================================================================

set -e

# -- Configuration --

WAZUH_PATH="/var/ossec"
INTEGRATION_DIR="${WAZUH_PATH}/integrations"
OSSEC_CONF="${WAZUH_PATH}/etc/ossec.conf"
ENRICHMENT_LOG="${WAZUH_PATH}/logs/ollama-enrichment.log"
DEBUG_LOG="${WAZUH_PATH}/logs/ollama-enrichment-debug.log"
CONFIG_FILE="${WAZUH_PATH}/etc/ollama-enrichment.conf"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONNECTIVITY_TIMEOUT_SECONDS=5

echo "=== Ollama LLM Enrichment Integration Deployment ==="
echo ""

# -- Pre-flight checks --

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

if [ ! -d "${WAZUH_PATH}" ]; then
    echo "ERROR: Wazuh not found at ${WAZUH_PATH}"
    exit 1
fi

# -- Step 1: Install integration scripts --

echo "[1/5] Installing integration scripts..."

cp "${SCRIPT_DIR}/custom-ollama-enrichment"    "${INTEGRATION_DIR}/"
cp "${SCRIPT_DIR}/custom-ollama-enrichment.py" "${INTEGRATION_DIR}/"

chmod 750  "${INTEGRATION_DIR}/custom-ollama-enrichment"
chmod 750  "${INTEGRATION_DIR}/custom-ollama-enrichment.py"
chown root:wazuh "${INTEGRATION_DIR}/custom-ollama-enrichment"
chown root:wazuh "${INTEGRATION_DIR}/custom-ollama-enrichment.py"

echo "    Installed to ${INTEGRATION_DIR}/"

# -- Step 2: Create log files --

echo "[2/5] Creating log files..."

touch "${ENRICHMENT_LOG}" "${DEBUG_LOG}"
chown wazuh:wazuh "${ENRICHMENT_LOG}" "${DEBUG_LOG}"
chmod 660 "${ENRICHMENT_LOG}" "${DEBUG_LOG}"

echo "    Audit log:  ${ENRICHMENT_LOG}"
echo "    Debug log:  ${DEBUG_LOG}"

# -- Step 3: Create config file for indexer credentials --

echo "[3/5] Checking config file..."

if [ -f "${CONFIG_FILE}" ]; then
    echo "    Config file already exists at ${CONFIG_FILE}"
else
    cat > "${CONFIG_FILE}" <<'CONF'
# Ollama LLM Alert Enrichment - Runtime Configuration
# Read by custom-ollama-enrichment.py at startup. Carries the
# script's runtime settings that do not belong in ossec.conf
# (indexer credentials and TLS options).
#
# Wazuh integration wiring (Ollama URL, model, alert threshold)
# lives in the <integration> block in ossec.conf.

# --- Wazuh Indexer (OpenSearch) ---
indexer_url=https://127.0.0.1:9200
indexer_user=admin
indexer_pass=admin

# TLS verification for the indexer connection.
# Defaults to 'true' (secure). The Wazuh OVA uses self-signed certs,
# so this deploy script writes 'false' for out-of-the-box compatibility.
# Set to 'true' in production against a CA-signed indexer certificate.
indexer_verify_tls=false

# Optional CA bundle for verify_tls=true with an internal CA:
#indexer_ca_path=/etc/pki/ca-trust/source/anchors/internal-ca.pem
CONF
    chown root:wazuh "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
    echo "    Created ${CONFIG_FILE} (root:wazuh, 640)"
    echo "    Edit this file if your indexer credentials differ from the defaults."
fi

# -- Step 4: Configure ossec.conf --

echo "[4/5] Checking ossec.conf..."

if grep -q "custom-ollama-enrichment" "${OSSEC_CONF}"; then
    echo "    Integration block already present in ossec.conf"
else
    INTEGRATION_BLOCK_FILE="${SCRIPT_DIR}/ossec-integration-block.xml"

    if [ ! -f "${INTEGRATION_BLOCK_FILE}" ]; then
        echo "    WARNING: ${INTEGRATION_BLOCK_FILE} not found."
        echo "    Add the integration block to ossec.conf manually."
    else
        echo "    Integration block not found in ossec.conf."
        read -p "    Insert it automatically? [y/N] " user_reply

        if [ "${user_reply}" = "y" ] || [ "${user_reply}" = "Y" ]; then
            # Insert the block before the closing </ossec_config> tag.
            # Uses a temp file to avoid sed escape issues across platforms.
            temp_conf=$(mktemp)
            awk -v block="$(cat "${INTEGRATION_BLOCK_FILE}")" \
                '/<\/ossec_config>/ { print block }1' \
                "${OSSEC_CONF}" > "${temp_conf}"
            cp "${temp_conf}" "${OSSEC_CONF}"
            rm -f "${temp_conf}"

            if grep -q "custom-ollama-enrichment" "${OSSEC_CONF}"; then
                echo "    Integration block inserted successfully"
            else
                echo "    WARNING: Auto-insert may have failed."
                echo "    Add the block from ossec-integration-block.xml manually."
            fi
        else
            echo "    Skipped. Add the block manually before restarting."
        fi
    fi
fi

# -- Step 5: Verify installation and test connectivity --

echo "[5/5] Verifying..."
echo ""
echo "    Integration scripts:"
ls -la "${INTEGRATION_DIR}/custom-ollama-enrichment"*
echo ""

# Test Ollama connectivity
OLLAMA_URL="${1:-http://localhost:11434}"
echo "    Testing Ollama at ${OLLAMA_URL}..."
if curl -s --connect-timeout "${CONNECTIVITY_TIMEOUT_SECONDS}" \
    "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
    echo "    Ollama is reachable"
else
    echo "    WARNING: Cannot reach Ollama at ${OLLAMA_URL}"
    echo "    Check OLLAMA_HOST=0.0.0.0 and firewall rules on the Ollama host"
fi

# Test Wazuh Indexer connectivity
echo "    Testing Wazuh Indexer..."
# Read credentials from the config file created in step 3
INDEXER_CREDS="admin:admin"
if [ -f "${CONFIG_FILE}" ]; then
    idx_user=$(grep '^indexer_user=' "${CONFIG_FILE}" | cut -d= -f2 | xargs)
    idx_pass=$(grep '^indexer_pass=' "${CONFIG_FILE}" | cut -d= -f2 | xargs)
    if [ -n "${idx_user}" ] && [ -n "${idx_pass}" ]; then
        INDEXER_CREDS="${idx_user}:${idx_pass}"
    fi
fi
indexer_health=$(curl -sk -u "${INDEXER_CREDS}" \
    "https://127.0.0.1:9200/_cluster/health" 2>/dev/null \
    | grep -o '"status":"[^"]*"' | head -1)
if [ -n "${indexer_health}" ]; then
    echo "    Indexer is reachable (${indexer_health})"
else
    echo "    WARNING: Cannot reach Wazuh Indexer at https://127.0.0.1:9200"
fi

# -- Done --

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Next steps:"
echo "  1. Ensure the integration block is in ${OSSEC_CONF}"
echo "  2. Enable debug logging (optional):"
echo "       echo 'integrator.debug=2' >> ${WAZUH_PATH}/etc/local_internal_options.conf"
echo "  3. Restart the Wazuh manager:"
echo "       systemctl restart wazuh-manager"
echo "  4. Trigger a level 10+ alert to test enrichment"
echo "  5. Check the dashboard for data.ai_enrichment fields on the alert"
