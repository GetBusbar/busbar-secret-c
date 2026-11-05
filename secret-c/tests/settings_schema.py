#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run against the compiled settings_schema.c probe; requires Python jsonschema."""
import json
from pathlib import Path
import subprocess
import sys

import jsonschema

probe = str(Path(sys.argv[1]).resolve())
schema = json.loads(subprocess.check_output([probe, "--schema"]))
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema)
cases = [
    ('{"values":{}}', True),
    ('{"values":{"name":"example"}}', True),
    ('null', False),
    ('{}', False),
    ('[]', False),
    ('{"values":null}', False),
    ('{"values":{"":"example"}}', False),
    ('{"values":{"name":""}}', False),
    ('{"values":{"name":5}}', False),
    ('{"values":{},"unknown":0}', False),
    (json.dumps({"values": {"n" * 1024: "v" * 1024}}), True),
    (json.dumps({"values": {"n" * 1025: "v"}}), False),
    (json.dumps({"values": {"n": "v" * 1025}}), False),
]
for text, accepted in cases:
    assert validator.is_valid(json.loads(text)) == accepted, ("schema", text)
    result = subprocess.run([probe, "--validate", text], check=False)
    assert result.returncode == (0 if accepted else 1), ("lifecycle", text)
assert subprocess.run([probe, "--validate", ""], check=False).returncode == 1
assert subprocess.run([probe, "--validate", '{"values":{},"values":{}}'], check=False).returncode == 1
# These lexical/byte limits cannot be expressed by standard JSON Schema character counts.
assert schema["x-maxSettingsBytes"] == 8192
assert schema["properties"]["values"]["additionalProperties"]["x-maxUtf8Bytes"] == 1024
assert schema["properties"]["values"]["additionalProperties"]["writeOnly"] is True
for text in [json.dumps({"values": {"n": "é" * 513}}, ensure_ascii=False),
             '{"values":{}}' + ' ' * 8192]:
    assert subprocess.run([probe, "--validate", text], check=False).returncode == 1
print(f"PASS: {len(cases)} schema/parser pairs, absent settings, duplicate and byte limits")
