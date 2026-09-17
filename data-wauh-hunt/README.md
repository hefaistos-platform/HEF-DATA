# HEFAISTOS Wazuh Hunting Dataset

This folder contains a Wazuh/OpenSearch **hunting query** RAG dataset —
DSL queries executed against the Wazuh indexer's alert index
(`wazuh-alerts-*`, plus `wazuh-states-vulnerabilities*` for a couple of
vulnerability-search entries) to hunt for adversary behavior in already-
ingested telemetry.

This is a **different, unrelated dataset** from `data-wazuh/
hefaistos_wazuh_dataset.jsonl` in this same repo, which is a Wazuh
**rule-engine XML** corpus (`<rule id=... level=...>` decoder/detection-rule
definitions for Wazuh's own detection engine, sourced from
`socfortress/Wazuh-Rules`). Do not conflate the two:

| | `data-wazuh/` | `data-wauh-hunt/` (this folder) |
|---|---|---|
| Content | Wazuh rule-engine XML (`<rule>`/`<decoder>`) | OpenSearch/Wazuh-indexer query DSL |
| Purpose | Feeds Arkona Forge's `WazuhTranspiler` rule-authoring lane | Feeds Arkona Forge's `wazuh_hunt` hunting-generation lane and reference RAG |
| Record shape | `messages[]` chat-style JSONL (system/user/assistant) | Flat JSON object per line |
| Consumer | Rule transpilation / rule-engine authoring | `WazuhReferenceSyncService` / Qdrant hunting-reference retrieval |

- Dataset file: `data-wauh-hunt/hefaistos_wazuh_hunting_dataset.jsonl`
- Consuming project: [Arkona Forge](https://github.com/th3r3d/Arkona-Forge)
  (`backend/app/services/wazuh_reference_sync.py`,
  `WAZUH_REFERENCE_GITHUB_DATASET_PATH`)
- Built by: research pass across Wazuh's own documentation, the Wazuh
  indexer API docs, `socfortress/Wazuh-Rules` and
  `socfortress/CoPilot-Search-Queries` GitHub repos, and public community
  writeups on Wazuh threat hunting. Entries with no single canonical
  source are marked `"source": "derived pattern, no single source"`
  rather than an invented URL.

## JSONL record shape

Each line is one flat JSON object:

```json
{
  "title": "SSH Brute Force by Source IP — High Severity (Level >= 10)",
  "wazuh": "{\"query\": {\"bool\": {\"must\": [...]}}}",
  "language": "wazuh",
  "source": "Wazuh docs: rule reference (rule 5763, 5712, 5720)",
  "description": "Detects repeated high-severity SSH authentication failures from a single source IP within a 24h window.",
  "technique_code": "T1110",
  "tables": ["wazuh-alerts-*"]
}
```

Field notes:

- `wazuh` — the actual OpenSearch query DSL, serialized as a JSON **string**
  (not a nested object), matching how Arkona Forge's KQL/EQL reference
  datasets store their query text.
- `language` — always the literal string `"wazuh"` in this file;
  Arkona Forge's parser normalizes this to its internal `wazuh_hunt` query
  language on ingest (see the naming-collision note in Arkona Forge's own
  docs — `wazuh` is reserved there for the rule-XML transpile format, so the
  hunting lane is namespaced `wazuh_hunt` downstream of this dataset).
- `technique_code` — MITRE ATT&CK technique ID when applicable, empty
  string otherwise. 33 unique technique codes appear across 39 tagged
  entries; 14 entries are intentionally technique-free general-purpose
  hunts (severity triage, FIM baseline, compliance/CVE lookups).
- `tables` — single-element array with the index pattern the query targets.

## Coverage

53 entries across: brute force / credential access, privilege escalation,
persistence, suspicious process execution, file integrity monitoring,
network anomalies, defense evasion / log tampering, lateral movement,
reconnaissance / discovery, credential dumping, service creation, and
general triage / vulnerability search.

## Validation

Validated against Arkona Forge's real consuming code
(`WazuhReferenceDatasetParser.parse_jsonl()` /
`WazuhReferenceSyncService.sync_once()`): all 53 lines parse as valid JSON,
all 53 records ingest successfully, 0 invalid records, 0 warnings.

## Regeneration / expansion

No automated build script yet (unlike `data-wazuh/`'s
`scripts/build_wazuh_dataset.py`) — this dataset was hand-researched, not
derived mechanically from a single upstream source. Expanding it means
adding more hand-verified entries in the same flat JSON-line shape above,
covering additional MITRE techniques or Wazuh-specific detection use cases
not yet represented.
