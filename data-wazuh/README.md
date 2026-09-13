# HEFAISTOS Wazuh Dataset

This folder contains a Wazuh RAG dataset built to match the existing HEFAISTOS JSONL style used in the KQL, EQL, and SPL datasets.

- Dataset file: `data-wazuh/hefaistos_wazuh_dataset.jsonl`
- Source repository: `https://github.com/socfortress/Wazuh-Rules`
- Source snapshot used for initial build: local clone at `/tmp/Wazuh-Rules`

## Why this format exists

Wazuh rules are not a single query language like KQL/EQL/SPL. They are XML-based detection logic with:

- Rule chaining (`if_sid`, `if_group`, `if_matched_sid`, `if_matched_group`)
- Correlation attributes (`frequency`, `timeframe`)
- Field extraction dependencies via decoders
- Rule-group hierarchy and file-level provenance

To make retrieval useful for generation and detection engineering workflows, the dataset is emitted as atomic records (rule/decoder) plus file-level context records.

## JSONL record shape

Each line in `hefaistos_wazuh_dataset.jsonl` is one JSON object with this same outer structure used by existing HEFAISTOS data:

```json
{
  "messages": [
    {"role":"system","content":"...schema..."},
    {"role":"user","content":"Title: ..."},
    {"role":"assistant","content":"metadata comments + XML snippet"}
  ]
}
```

## Record types

The dataset includes three record types in assistant metadata comments:

1. `wazuh_rule`
- One record per `<rule id="...">...</rule>` block.
- Captures key fields such as: group name, rule id, level, dependency tags, conditions, list lookups, mitre ids, options, and raw XML.

2. `wazuh_decoder`
- One record per `<decoder ...>...</decoder>` block.
- Captures decoder chain details such as: decoder name, parent, prematch, regex, order fields, and raw XML.

3. `wazuh_bundle`
- One record per XML file for broad context.
- Contains source path, counts, top-level groups, and a file preview.

## Initial build statistics

Generated from 75 XML files in `socfortress/Wazuh-Rules`:

- Rule records: 2212
- Decoder records: 105
- Bundle records: 75
- Total JSONL lines: 2392

## Regeneration

Use the included script:

- Script: `scripts/build_wazuh_dataset.py`
- Command:

```bash
/opt/homebrew/bin/python3 scripts/build_wazuh_dataset.py \
  --repo /tmp/Wazuh-Rules \
  --out data-wazuh/hefaistos_wazuh_dataset.jsonl
```

If needed, reclone source repo first:

```bash
git clone --depth 1 https://github.com/socfortress/Wazuh-Rules.git /tmp/Wazuh-Rules
```

## Validation

Use the validation utility before ingesting into HEFAISTOS:

- Script: `scripts/validate_wazuh_dataset.py`
- Command:

```bash
/opt/homebrew/bin/python3 scripts/validate_wazuh_dataset.py \
  --input data-wazuh/hefaistos_wazuh_dataset.jsonl
```

Validator checks:

- Every line is valid JSON
- Every record has exactly 3 messages with roles `system`, `user`, `assistant`
- Assistant metadata includes `Record Type` and `Source`
- `wazuh_rule` title/rule-id/XML consistency
- `wazuh_decoder` title/XML consistency
- `wazuh_bundle` title/count markers consistency

## Suggested HEFAISTOS ingestion strategy

Use `messages[2].content` as the embedding text body. It contains:

- High-signal normalized metadata comments for retrieval
- The exact XML snippet for reconstruction

Recommended filters/payload metadata during ingestion:

- `platform = wazuh`
- `record_type = wazuh_rule | wazuh_decoder | wazuh_bundle`
- `source_path`
- `rule_id` (when present)
- `group_name` (when present)

## Practical retrieval patterns

- For rule generation: filter `record_type = wazuh_rule`
- For parser/field issues: filter `record_type = wazuh_decoder`
- For broad context by integration: filter `record_type = wazuh_bundle` and `source_path contains <integration-folder>`

## Notes

- This dataset does not modify upstream rule IDs.
- Upstream XML can contain non-uniform formatting; parser is regex-based and optimized for extraction robustness.
- Re-run generation whenever `socfortress/Wazuh-Rules` changes.
