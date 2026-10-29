#!/usr/bin/env python3
"""Verify the committed selection against the exact downloaded NIST CAVP ZIP."""
import hashlib
import json
import pathlib
import re
import zipfile

base = pathlib.Path(__file__).resolve().parent
root = base.parents[1]
fixture = root / 'zeroj-circuit-lib/src/test/resources/standard-vectors/nist-sha2-selected.json'
source = json.loads(fixture.read_text())
archive = base / 'build/shabytetestvectors.zip'
actual_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
if actual_hash != source['zip_sha256']:
    raise SystemExit('NIST ZIP hash mismatch; do not update the pin automatically')
with zipfile.ZipFile(archive) as files:
    parsed = {}
    for case in source['cases']:
        name = case['source_file']
        if name not in parsed:
            text = files.read(name).decode('ascii')
            rows = re.findall(r'Len\s*=\s*(\d+)\s+Msg\s*=\s*([0-9a-fA-F]+)\s+MD\s*=\s*([0-9a-fA-F]+)', text)
            parsed[name] = {(int(bits), '' if int(bits) == 0 else message.lower(), digest.lower())
                            for bits, message, digest in rows}
        expected = (case['length_bytes'] * 8, case['message_hex'], case['digest_hex'])
        if expected not in parsed[name]:
            raise SystemExit(f'Selected case is not in the pinned official file: {name} / {expected[0]} bits')
result = {'cases_verified': len(source['cases']), 'source': source['source'],
          'zip_sha256': actual_hash, 'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest()}
(base / 'build/nist-source-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
