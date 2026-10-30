# Synthetic lab dataset

Five days (2026-10-05 to 2026-10-09 UTC) of **fully synthetic** Windows telemetry for a fictional company, Northwind Labs (`LAB.EXAMPLE`). The set has about 75 hosts and normal day-to-day noise. Hidden in it is one ransomware intrusion that touches every playbook from HL-0001 to HL-0010. **Benign look-alikes are planted on purpose**, so each hunt returns results you have to triage.

All hosts, users and IPs are invented. External addresses come from the documentation ranges `198.51.100.0/24` and `203.0.113.0/24`. The dataset is TLP:CLEAR and safe to share.

## Files

| File | Schema | Use with |
|---|---|---|
| `lab/sysmon/process_creation.jsonl` | Sysmon Event ID 1 (`Image`, `CommandLine`, `ParentImage`, `OriginalFileName`, `User`, `Computer`, ...) | Sigma `process_creation`, SPL |
| `lab/sysmon/registry_set.jsonl` | Sysmon Event ID 13 (`TargetObject`, `Details`, `Image`) | Sigma `registry_set`, SPL |
| `lab/sysmon/network_connection.jsonl` | Sysmon Event ID 3 (`DestinationIp`, `DestinationHostname`, `DestinationPort`) | SPL pivots |
| `lab/security/security.jsonl` | Security 4624 / 4769 (`TargetUserName`, `ServiceName`, `TicketEncryptionType`, `IpAddress`, `LogonType`) | Sigma `service: security`, SPL |
| `lab/mde/DeviceProcessEvents.csv` | Defender XDR Advanced Hunting schema (subset) | KQL |
| `lab/mde/DeviceRegistryEvents.csv` | Defender XDR schema (subset) | KQL |
| `lab/mde/DeviceNetworkEvents.csv` | Defender XDR schema (subset) | KQL |
| `lab/sentinel/SecurityEvent.csv` | Sentinel `SecurityEvent` schema (subset) | KQL |
| `answer_key.json` | Ground truth per hunt | **Facilitators only** |
| `generate_lab_data.py` | Deterministic generator (Python 3.9+, stdlib only) | Rebuild or extend the lab |

Each event has a `LabEventId` (`ReportId` in the Defender tables), so findings can be checked against the answer key. Both formats describe the same events.

## Loading the data

**Splunk** (free trial or Splunk Enterprise dev license)

1. Create an index called `windows`, or change `index=windows` in the SPL files.
2. Go to *Settings → Add Data → Upload*. Upload each `.jsonl` file with sourcetype `_json` and index `windows`.
3. Set the timestamp to the `UtcTime` field, format `%Y-%m-%dT%H:%M:%S.%3NZ`.
4. In each query, replace `earliest=-14d` with `earliest=0`. The queries already use `Computer` for the host name.

**Azure Data Explorer** (free cluster at <https://dataexplorer.azure.com/freecluster>)

1. Create a database. Then use *Get data → Local file* to ingest each CSV into a table with the **same name as the file**: `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents` and `SecurityEvent`.
2. Let the wizard infer the schema, then set `Timestamp` / `TimeGenerated` to `datetime`.
3. In each KQL file, set `let lookback = 3650d;`. Queries written for Sentinel use `TimeGenerated`, and the Defender ones use `Timestamp`.

**No SIEM?** `python tests/test_lab_detections.py` converts every Sigma rule to SQL and runs it against the JSONL files in SQLite (`pip install pysigma-backend-sqlite`). You can also open the CSVs in any notebook.

## Regenerating

```bash
python data/generate_lab_data.py
```

The output is byte-for-byte reproducible (fixed seed). If you add a scenario, tag its events in the generator with `(hunt_id, "malicious" | "benign_match", note)`. The answer key and the CI test will then pick it up.
