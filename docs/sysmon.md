# Sysmon Integration on Windows Agents

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Sysinternals) produces detailed endpoint telemetry - process creation, network connections, image loads, driver loads, file creation, and more - with MITRE ATT&CK technique annotations when paired with a suitable config. Wazuh 4.14.x ships with built-in Sysmon decoders and rules (IDs 61600+ and 92000+), so the server side needs no ruleset changes. Sysmon alerts at or above the configured enrichment threshold are automatically enriched by the Ollama pipeline, exactly like native Wazuh alerts.

This doc covers the recommended deployment path used in this project: Sysmon installed per-host on each Windows agent, plus a centralised Wazuh agent-side `agent.conf` pushed from the manager via a group. The group approach scales cleanly as more Windows endpoints are onboarded - no per-host `ossec.conf` edits required.

## 1. Install Sysmon on each Windows agent

Open an admin PowerShell on each Windows agent. The config used here is Olaf Hartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular) (balanced / medium verbosity), sourced from the Wazuh blog post [Emulation of ATT&CK techniques and detection with Wazuh](https://wazuh.com/blog/emulation-of-attck-techniques-and-detection-with-wazuh/):

```powershell
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:TEMP\Sysmon.zip
Expand-Archive -Path $env:TEMP\Sysmon.zip -DestinationPath $env:TEMP\Sysmon -Force
Invoke-WebRequest -Uri "https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml" -OutFile "$env:TEMP\Sysmon\sysmonconfig.xml"
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\Sysmon\sysmonconfig.xml"
```

Verify Sysmon is running and logging events:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

Schema-version warnings (e.g. `sysmonconfig.xml` is 4.90 vs Sysmon binary 4.91) can be ignored - Sysmon accepts configs from older schema versions.

## 2. Assign Windows agents to a group on the Wazuh manager

On the Wazuh server (as root):

```bash
# Create the group if it doesn't already exist
sudo /var/ossec/bin/agent_groups -a -g os_windows -q

# Assign each Windows agent by ID (find IDs with `agent_control -l`)
sudo /var/ossec/bin/agent_groups -a -i 002 -g os_windows -q
sudo /var/ossec/bin/agent_groups -a -i 003 -g os_windows -q

# Verify
sudo /var/ossec/bin/agent_groups -l
```

Expected output:

```
Groups (3):
  default (3)
  os_ubuntu (1)
  os_windows (2)
```

Agents retain the `default` group and pick up any additional group memberships alongside it.

## 3. Push the Sysmon localfile directive via the group's `agent.conf`

Edit `/var/ossec/etc/shared/os_windows/agent.conf` on the manager:

```xml
<!-- /var/ossec/etc/shared/os_windows/agent.conf -->
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

The manager pushes this config to every agent in the `os_windows` group on the next sync (typically within a minute). No per-agent `ossec.conf` edits are needed, and new Windows endpoints only require group assignment at enrolment to inherit the same Sysmon collection.

## 4. Verify Sysmon events arriving on the Wazuh server

```bash
grep -i sysmon /var/ossec/logs/alerts/alerts.json | tail -5
```

Or in the Wazuh dashboard:

- Filter by `rule.groups: sysmon`
- Filter by `data.win.system.providerName: Microsoft-Windows-Sysmon`
- Filter by `agent.id: 002` / `agent.id: 003`

Sysmon alerts are decoded automatically; no custom decoder is required.

## 5. Trigger a test Sysmon alert

Encoded PowerShell is a reliable trigger because sysmon-modular flags it via multiple rules (process creation, image load, executable drop):

```powershell
# On a Windows agent - decodes to 'Start-Sleep -Seconds 1' (harmless)
powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQA=
```

This typically fires at level 12-15, above the default enrichment threshold of 10, so the pipeline will enrich it automatically. Watch `/var/ossec/logs/ollama-enrichment.log` on the Wazuh server for the enrichment result.

## Alternative: per-agent `ossec.conf` edit

If you only have a single Windows agent or prefer not to use groups, add the same block to `C:\Program Files (x86)\ossec-agent\ossec.conf` on the agent and restart the service:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
Restart-Service WazuhSvc
```

The group-based approach is preferred once you have more than one Windows endpoint; the per-agent approach is fine for single-host tests.

## Notes

- Sysmon alerts on the default sysmon-modular config fire at a relatively high volume. If you lower the enrichment threshold below 10 (e.g. for FIM coverage at level 7), high-frequency Sysmon rules like 92910 (process access) can saturate the sequential enrichment queue. Add per-rule filters in the integration block (`<rule_id>` excludes) or keep the threshold at 10 for production use. See §6.4 of the technical report for the full observation.
- Many Sysmon alerts are expected false positives on a normal Windows host (OneDrive accessing Explorer, PowerShell automation libraries, Application Compatibility Database). The LLM enrichment distinguishes these from genuine threats via the `false_positive_likelihood` field - see §4 of the technical report for examples.
