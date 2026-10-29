#!/usr/bin/env python3
"""Recheck retained public SHA-2 development proof fixtures, without running setup."""
import datetime
import hashlib
import json
import pathlib
import platform
import subprocess

BASE = pathlib.Path(__file__).resolve().parent
ROOT = BASE.parents[1]
SNARKJS = BASE.parent / 'sha2-circom/node_modules/snarkjs'
BUILD = BASE / 'build'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    runner_path = pathlib.Path(__file__)
    runner_hash = digest(runner_path)
    BUILD.mkdir(exist_ok=True)
    result_path = BUILD / 'result.json'
    result_path.unlink(missing_ok=True)
    if json.loads((SNARKJS / 'package.json').read_text())['version'] != '0.7.6':
        raise RuntimeError('Pinned snarkjs 0.7.6 required; run ../sha2-circom/bootstrap.sh')
    checks = []
    files = {'provenance.json': digest(BASE / 'provenance.json')}
    for case, limbs in [('sha256-32', 2), ('sha512-32', 4)]:
        folder = BASE / case
        message = bytes.fromhex((folder / 'message.hex').read_text())
        expected_digest = hashlib.new(case.split('-')[0], message).digest()
        expected_limbs = [int.from_bytes(expected_digest[i:i+16], 'big')
                          for i in range(0, len(expected_digest), 16)]
        if len(message) != 32 or expected_digest.hex() != (folder / 'digest.hex').read_text().strip():
            raise RuntimeError('Message/digest fixture mismatch: ' + case)
        if [int(x) for x in json.loads((folder / 'public.json').read_text())] != expected_limbs:
            raise RuntimeError('Full public digest limb mismatch: ' + case)
        for name in ['message.hex', 'digest.hex', 'result.json']:
            files[f'{case}/{name}'] = digest(folder / name)
        vectors = [('valid', 'public.json', 'proof.json', True)]
        vectors += [(f'wrong-limb-{i}', f'public-wrong-{i}.json', 'proof.json', False)
                    for i in range(limbs)]
        vectors += [('negated-a', 'public.json', 'proof-negated-a.json', False)]
        for label, public_file, proof_file, valid in vectors:
            paths = [folder / 'verification_key.json', folder / public_file, folder / proof_file]
            for path in paths:
                name, identity = str(path.relative_to(BASE)), digest(path)
                if name in files and files[name] != identity:
                    raise RuntimeError('Proof fixture changed between checks: ' + name)
                files[name] = identity
            args = ['node', str(SNARKJS / 'build/cli.cjs'), 'groth16', 'verify'] + [str(p) for p in paths]
            process = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=60)
            output = process.stdout + '\n' + process.stderr
            (BUILD / f'{case}-{label}.log').write_text(output)
            expected_exit, expected_text = (0, 'OK!') if valid else (1, 'Invalid proof')
            if process.returncode != expected_exit or expected_text not in output:
                raise RuntimeError(f'{case}/{label}: unexpected verifier result {process.returncode}\n{output}')
            checks.append({'case': case, 'check': label, 'expected_valid': valid,
                           'exit_code': process.returncode, 'expected_verifier_text': expected_text,
                           'verification_key': str(paths[0].relative_to(BASE)),
                           'public_inputs': str(paths[1].relative_to(BASE)),
                           'proof': str(paths[2].relative_to(BASE))})
            print(f'PASS {case}/{label}: expected validity={valid}', flush=True)
    # Bind the result to the exact retained artifacts, and reject mid-run edits.
    if any(digest(BASE / name) != expected for name, expected in files.items()):
        raise RuntimeError('Proof fixtures changed during verification')
    if digest(runner_path) != runner_hash:
        raise RuntimeError('Verification runner changed during verification')
    result = {'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'Public fixtures with insecure single-party development setup; no production claim',
              'curve': 'BLS12-381', 'snarkjs': '0.7.6',
              'node': subprocess.check_output(['node', '--version'], text=True).strip(),
              'platform': platform.platform(), 'runner_sha256': runner_hash,
              'snarkjs_cli_sha256': digest(SNARKJS / 'build/cli.cjs'),
              'npm_lock_sha256': digest(BASE.parent / 'sha2-circom/package-lock.json'),
              'valid_proofs_accepted': sum(row['expected_valid'] for row in checks),
              'invalid_statements_or_proofs_rejected': sum(not row['expected_valid'] for row in checks),
              'artifact_sha256': files, 'checks': checks}
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Wrote {result_path.relative_to(ROOT)}', flush=True)


if __name__ == '__main__':
    main()
