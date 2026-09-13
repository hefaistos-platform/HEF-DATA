#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


RECORD_TYPE_RE = re.compile(r"^//\s*Record Type:\s*(\w+)\s*$", re.MULTILINE)
RULE_ID_RE = re.compile(r"^//\s*Rule ID:\s*(\d+)\s*$", re.MULTILINE)
SOURCE_RE = re.compile(r"^//\s*Source:\s*socfortress/Wazuh-Rules::(.+)$", re.MULTILINE)
TITLE_RULE_RE = re.compile(r"^Title:\s+(.+)#rule-(\d+)\s*$")
TITLE_DECODER_RE = re.compile(r"^Title:\s+(.+)#decoder-(.+)\s*$")
TITLE_BUNDLE_RE = re.compile(r"^Title:\s+(.+)#bundle\s*$")


def fail(errors, line_no, message):
    errors.append(f"line {line_no}: {message}")


def validate_line(line_no: int, raw_line: str, errors: list, stats: Counter):
    try:
        obj = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        fail(errors, line_no, f"invalid JSON ({exc})")
        return

    if not isinstance(obj, dict):
        fail(errors, line_no, "top-level JSON value must be an object")
        return

    messages = obj.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        fail(errors, line_no, "messages must be a list with exactly 3 items")
        return

    expected_roles = ["system", "user", "assistant"]
    for idx, expected_role in enumerate(expected_roles):
        msg = messages[idx]
        if not isinstance(msg, dict):
            fail(errors, line_no, f"messages[{idx}] must be an object")
            return
        if msg.get("role") != expected_role:
            fail(errors, line_no, f"messages[{idx}].role must be '{expected_role}'")
            return
        if not isinstance(msg.get("content"), str) or not msg.get("content").strip():
            fail(errors, line_no, f"messages[{idx}].content must be a non-empty string")
            return

    user_title = messages[1]["content"].strip()
    assistant_text = messages[2]["content"]

    record_match = RECORD_TYPE_RE.search(assistant_text)
    if not record_match:
        fail(errors, line_no, "assistant content missing '// Record Type: ...' marker")
        return

    record_type = record_match.group(1)
    stats[f"record_type:{record_type}"] += 1

    if not SOURCE_RE.search(assistant_text):
        fail(errors, line_no, "assistant content missing valid Source marker")

    if record_type == "wazuh_rule":
        title_match = TITLE_RULE_RE.match(user_title)
        if not title_match:
            fail(errors, line_no, "rule record title must match 'Title: <path>#rule-<id>'")
            return

        rule_id_match = RULE_ID_RE.search(assistant_text)
        if not rule_id_match:
            fail(errors, line_no, "rule record missing '// Rule ID: <id>'")
            return

        title_rule_id = title_match.group(2)
        meta_rule_id = rule_id_match.group(1)
        if title_rule_id != meta_rule_id:
            fail(errors, line_no, f"title rule id ({title_rule_id}) != metadata rule id ({meta_rule_id})")

        if not re.search(rf"<rule\b[^>]*\bid=\"{re.escape(meta_rule_id)}\"[^>]*>", assistant_text):
            fail(errors, line_no, "rule XML snippet does not contain matching <rule ... id=...>")

    elif record_type == "wazuh_decoder":
        if not TITLE_DECODER_RE.match(user_title):
            fail(errors, line_no, "decoder record title must match 'Title: <path>#decoder-<name>'")
        if "<decoder " not in assistant_text:
            fail(errors, line_no, "decoder record missing <decoder ...> XML snippet")

    elif record_type == "wazuh_bundle":
        if not TITLE_BUNDLE_RE.match(user_title):
            fail(errors, line_no, "bundle record title must match 'Title: <path>#bundle'")
        if "// Rule Count:" not in assistant_text:
            fail(errors, line_no, "bundle record missing '// Rule Count:' metadata")
        if "// Decoder Count:" not in assistant_text:
            fail(errors, line_no, "bundle record missing '// Decoder Count:' metadata")

    else:
        fail(errors, line_no, f"unknown record type '{record_type}'")


def main():
    parser = argparse.ArgumentParser(description="Validate HEFAISTOS Wazuh JSONL dataset integrity and schema markers.")
    parser.add_argument("--input", required=True, help="Path to data-wazuh/hefaistos_wazuh_dataset.jsonl")
    parser.add_argument("--max-errors", type=int, default=50, help="Maximum number of errors to print before stopping")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: dataset file not found: {input_path}")
        return 2

    errors = []
    stats = Counter()
    total = 0

    with input_path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, 1):
            raw_line = raw_line.rstrip("\n")
            if not raw_line.strip():
                fail(errors, line_no, "empty line is not allowed in JSONL")
                if len(errors) >= args.max_errors:
                    break
                continue

            total += 1
            validate_line(line_no, raw_line, errors, stats)
            if len(errors) >= args.max_errors:
                break

    print(f"Checked lines: {total}")
    print(f"wazuh_rule records: {stats.get('record_type:wazuh_rule', 0)}")
    print(f"wazuh_decoder records: {stats.get('record_type:wazuh_decoder', 0)}")
    print(f"wazuh_bundle records: {stats.get('record_type:wazuh_bundle', 0)}")

    if errors:
        print("Validation: FAILED")
        for err in errors:
            print(f"- {err}")
        return 1

    print("Validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
