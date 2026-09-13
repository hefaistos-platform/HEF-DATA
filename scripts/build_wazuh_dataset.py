#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def parse_attrs(opening_tag: str) -> dict:
    return dict(re.findall(r'(\w+)="([^"]*)"', opening_tag))


def extract_tag_values(xml: str, tag: str):
    return [clean_text(m.group(1)) for m in re.finditer(rf"<{tag}>(.*?)</{tag}>", xml, flags=re.DOTALL)]


def extract_field_conditions(rule_xml: str):
    out = []
    for m in re.finditer(r'<field\s+name="([^"]+)">(.*?)</field>', rule_xml, flags=re.DOTALL):
        out.append((m.group(1), clean_text(m.group(2))))
    return out


def extract_list_lookups(rule_xml: str):
    out = []
    for m in re.finditer(r'<list\s+([^>]*)>(.*?)</list>', rule_xml, flags=re.DOTALL):
        attrs = parse_attrs(m.group(1))
        out.append((attrs.get('field', ''), attrs.get('lookup', ''), clean_text(m.group(2))))
    return out


def build_rule_record(source_path: str, group_name: str, rule_xml: str):
    opening = re.search(r'<rule\s+([^>]*)>', rule_xml)
    attrs = parse_attrs(opening.group(1)) if opening else {}

    rule_id = attrs.get('id', 'unknown')
    level = attrs.get('level', 'unknown')
    frequency = attrs.get('frequency', '')
    timeframe = attrs.get('timeframe', '')

    if_sid = extract_tag_values(rule_xml, 'if_sid')
    if_group = extract_tag_values(rule_xml, 'if_group')
    if_matched_sid = extract_tag_values(rule_xml, 'if_matched_sid')
    if_matched_group = extract_tag_values(rule_xml, 'if_matched_group')
    decoded_as = extract_tag_values(rule_xml, 'decoded_as')
    location = extract_tag_values(rule_xml, 'location')
    options = extract_tag_values(rule_xml, 'options')
    mitre_ids = extract_tag_values(rule_xml, 'id')
    # Exclude the rule id itself from MITRE ids if captured by generic extraction
    mitre_ids = [m for m in mitre_ids if not m.isdigit() or m != str(rule_id)]
    descriptions = extract_tag_values(rule_xml, 'description')
    rule_groups = extract_tag_values(rule_xml, 'group')

    field_conditions = extract_field_conditions(rule_xml)
    list_lookups = extract_list_lookups(rule_xml)

    lines = [
        '// Platform: Wazuh',
        '// Record Type: wazuh_rule',
        f'// Source: socfortress/Wazuh-Rules::{source_path}',
        f'// Group Name: {group_name}',
        f'// Rule ID: {rule_id}',
        f'// Level: {level}',
    ]

    if frequency:
        lines.append(f'// Frequency: {frequency}')
    if timeframe:
        lines.append(f'// Timeframe: {timeframe}')
    if if_sid:
        lines.append(f'// If SID: {", ".join(if_sid)}')
    if if_group:
        lines.append(f'// If Group: {", ".join(if_group)}')
    if if_matched_sid:
        lines.append(f'// If Matched SID: {", ".join(if_matched_sid)}')
    if if_matched_group:
        lines.append(f'// If Matched Group: {", ".join(if_matched_group)}')
    if decoded_as:
        lines.append(f'// Decoded As: {", ".join(decoded_as)}')
    if location:
        lines.append(f'// Location: {", ".join(location)}')
    if rule_groups:
        lines.append(f'// Rule Groups: {" | ".join(rule_groups)}')
    if options:
        lines.append(f'// Options: {", ".join(options)}')
    if mitre_ids:
        lines.append(f'// MITRE ATT&CK: {", ".join(mitre_ids)}')

    for name, pattern in field_conditions:
        lines.append(f'// Field Condition: {name} => {pattern}')

    for lf, lk, lp in list_lookups:
        lines.append(f'// List Lookup: field={lf}; lookup={lk}; list={lp}')

    if descriptions:
        lines.append('// Description:')
        for d in descriptions:
            lines.append(f'// {d}')

    lines.append('')
    lines.append(rule_xml.strip())

    title = f'Title: {source_path}#rule-{rule_id}'
    system_schema = (
        'Schema: WazuhRule '
        '(rule_id, level, group_name, dependencies, field_conditions, list_lookups, '
        'mitre_ids, decoded_as, options, source_path).'
    )

    return {
        'messages': [
            {'role': 'system', 'content': system_schema},
            {'role': 'user', 'content': title},
            {'role': 'assistant', 'content': '\n'.join(lines)},
        ]
    }


def build_decoder_record(source_path: str, decoder_xml: str):
    opening = re.search(r'<decoder\s+([^>]*)>', decoder_xml)
    attrs = parse_attrs(opening.group(1)) if opening else {}
    decoder_name = attrs.get('name', 'unknown')

    parent = extract_tag_values(decoder_xml, 'parent')
    prematch = extract_tag_values(decoder_xml, 'prematch')
    regex = extract_tag_values(decoder_xml, 'regex')
    order = extract_tag_values(decoder_xml, 'order')
    program_name = extract_tag_values(decoder_xml, 'program_name')

    lines = [
        '// Platform: Wazuh',
        '// Record Type: wazuh_decoder',
        f'// Source: socfortress/Wazuh-Rules::{source_path}',
        f'// Decoder Name: {decoder_name}',
    ]

    if parent:
        lines.append(f'// Parent: {", ".join(parent)}')
    if program_name:
        lines.append(f'// Program Name: {", ".join(program_name)}')
    if prematch:
        lines.append(f'// Prematch: {" | ".join(prematch)}')
    if regex:
        lines.append(f'// Regex: {" | ".join(regex)}')
    if order:
        lines.append(f'// Order Fields: {" | ".join(order)}')

    lines.append('')
    lines.append(decoder_xml.strip())

    title = f'Title: {source_path}#decoder-{decoder_name}'
    system_schema = 'Schema: WazuhDecoder (decoder_name, parent, prematch, regex, order_fields, source_path).'

    return {
        'messages': [
            {'role': 'system', 'content': system_schema},
            {'role': 'user', 'content': title},
            {'role': 'assistant', 'content': '\n'.join(lines)},
        ]
    }


def build_bundle_record(source_path: str, file_text: str, rule_count: int, decoder_count: int, group_names):
    preview = file_text.strip()
    if len(preview) > 8000:
        preview = preview[:8000] + '\n<!-- truncated -->'

    lines = [
        '// Platform: Wazuh',
        '// Record Type: wazuh_bundle',
        f'// Source: socfortress/Wazuh-Rules::{source_path}',
        f'// Rule Count: {rule_count}',
        f'// Decoder Count: {decoder_count}',
    ]
    if group_names:
        lines.append(f'// Top-level Groups: {", ".join(sorted(group_names))}')
    lines.append('// Description: File-level context record for broad retrieval and provenance.')
    lines.append('')
    lines.append(preview)

    return {
        'messages': [
            {'role': 'system', 'content': 'Schema: WazuhBundle (source_path, rule_count, decoder_count, top_level_groups, raw_xml_preview).'},
            {'role': 'user', 'content': f'Title: {source_path}#bundle'},
            {'role': 'assistant', 'content': '\n'.join(lines)},
        ]
    }


def build_group_ranges(text: str):
    token_pattern = re.compile(r'<group\s+name="([^"]+)">|</group>', flags=re.DOTALL)
    stack = []
    ranges = []

    for m in token_pattern.finditer(text):
        name = m.group(1)
        if name is not None:
            stack.append((name, m.start(), m.end()))
            continue

        if stack:
            open_name, open_start, _open_end = stack.pop()
            ranges.append((open_start, m.end(), open_name))

    return ranges


def iter_rules_global(text: str):
    pattern = re.compile(r'<rule\b[^>]*id="\d+"[^>]*>.*?</rule>', flags=re.DOTALL)
    for m in pattern.finditer(text):
        yield m.group(0), m.start()


def find_rule_group_name(rule_start: int, group_ranges):
    candidates = [g for g in group_ranges if g[0] <= rule_start <= g[1]]
    if not candidates:
        return 'ungrouped'
    candidates.sort(key=lambda x: x[1] - x[0])
    return candidates[0][2]


def iter_decoders(text: str):
    pattern = re.compile(r'<decoder\b[^>]*>.*?</decoder>', flags=re.DOTALL)
    for m in pattern.finditer(text):
        yield m.group(0)


def main():
    ap = argparse.ArgumentParser(description='Build HEFAISTOS Wazuh JSONL dataset from socfortress/Wazuh-Rules XML files.')
    ap.add_argument('--repo', required=True, help='Path to cloned socfortress/Wazuh-Rules repository')
    ap.add_argument('--out', required=True, help='Output JSONL path')
    args = ap.parse_args()

    repo = Path(args.repo)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    xml_files = sorted(repo.rglob('*.xml'))
    total_rules = 0
    total_decoders = 0
    total_bundles = 0

    with out.open('w', encoding='utf-8') as f:
        for xml_path in xml_files:
            rel = xml_path.relative_to(repo).as_posix()
            text = xml_path.read_text(encoding='utf-8', errors='replace')

            group_names = []
            file_rule_count = 0
            file_decoder_count = 0

            group_ranges = build_group_ranges(text)
            if group_ranges:
                group_names = sorted({g[2] for g in group_ranges})

            for rule_xml, rule_start in iter_rules_global(text):
                group_name = find_rule_group_name(rule_start, group_ranges)
                rec = build_rule_record(rel, group_name, rule_xml)
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
                total_rules += 1
                file_rule_count += 1

            for decoder_xml in iter_decoders(text):
                rec = build_decoder_record(rel, decoder_xml)
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
                total_decoders += 1
                file_decoder_count += 1

            if file_rule_count > 0 or file_decoder_count > 0:
                bundle = build_bundle_record(rel, text, file_rule_count, file_decoder_count, group_names)
                f.write(json.dumps(bundle, ensure_ascii=False) + '\n')
                total_bundles += 1

    print(f'Wrote: {out}')
    print(f'XML files scanned: {len(xml_files)}')
    print(f'Rule records: {total_rules}')
    print(f'Decoder records: {total_decoders}')
    print(f'Bundle records: {total_bundles}')


if __name__ == '__main__':
    main()
