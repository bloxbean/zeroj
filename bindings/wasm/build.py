#!/usr/bin/env python3
"""Compile explicit Java entry points. Generated images/logs stay under build/."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, time
ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'bindings/wasm'
PROFILES = {'hash': ('HashWeb', ['hash']), 'probe': ('PlatformProbeWeb', ['probe']),
            'circuit': ('CircuitWeb', ['circuit','groth16-verifier']),
            'crypto': ('CryptoWeb', ['bbs','pedersen']),
            'all': ('AllWeb', ['hash','pedersen','bbs','groth16-verifier','groth16-prover','elgamal','threshold','confidential-notes']),
            'confidential': ('ConfidentialWeb', ['elgamal','threshold','confidential-notes']),
            'verifier': ('VerifierWeb', ['groth16-verifier']), 'prover': ('ProverWeb', ['groth16-prover']),
            'unprotected': ('UnprotectedWeb', ['unprotected'])}
parser = argparse.ArgumentParser()
parser.add_argument('profiles', nargs='*', choices=list(PROFILES))
args = parser.parse_args()
home = Path(os.environ.get('GRAALVM_HOME', os.environ.get('JAVA_HOME', '')))
if not (home / 'bin/native-image').is_file():
    parser.error('Set GRAALVM_HOME to Oracle GraalVM 25.3.4.1+1.1')
if 'GRAALVM_VERSION="25.3.4.1' not in (home / 'release').read_text():
    parser.error('Expected pinned GraalVM 25.3.4.1 line')
env = {**os.environ, 'JAVA_HOME': str(home), 'PATH': str(home/'bin')+os.pathsep+os.environ['PATH']}
out = HERE / 'build'; out.mkdir(exist_ok=True)
def run(command, log):
    with log.open('w') as f:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text()[-8000:])
        raise SystemExit(result.returncode)
run([str(ROOT/'gradlew'), '-p', str(HERE), ':bundles:classpath', '--max-workers=2', '--console=plain'], out/'compile.log')
cp = (HERE/'bundles/build/classpath.txt').read_text()
binaryen = subprocess.check_output(['wasm-as','--version'],text=True).strip()
if binaryen != 'wasm-as version 132': raise SystemExit('Expected Binaryen 132, got '+binaryen)
inputs = hashlib.sha256()
for index, entry in enumerate(cp.split(os.pathsep)):
    path = Path(entry)
    inputs.update(str(index).encode()+b'\0')
    if not path.exists():
        inputs.update(b'absent-classpath-entry\0')
        continue
    for item in (sorted(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else [path]):
        inputs.update((str(item.relative_to(path)) if path.is_dir() else path.name).encode()+b'\0')
        inputs.update(hashlib.sha256(item.read_bytes()).digest())
inputs.update(Path(__file__).read_bytes())
inputs.update((home/'release').read_bytes())
if any('blst' in p.lower() for p in cp.split(os.pathsep)):
    raise SystemExit('Native blst classpath rejected')
for name in args.profiles or ['hash']:
    entry, capabilities = PROFILES[name]
    folder = out/'images'/name; folder.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    run([str(home/'bin/native-image'), '--tool:svm-wasm', '-J-Xmx6g', '--parallelism=4',
         '-cp', cp, '--exclude-config', r'.*zeroj-.*\.jar', 'META-INF/native-image/.*',
         '-o', str(folder/'engine'), '-H:+ReportExceptionStackTraces',
         '-H:AbortOnTypeReachable=org.zeroj.blst.*',
         '-H:AbortOnTypeReachable=supranational.blst.*',
         '-H:AbortOnTypeReachable=org.zeroj.crypto.setup.*',
         '-H:AbortOnTypeReachable=org.zeroj.bindings.circuit.Fixtures',
         '-H:AbortOnTypeReachable=org.zeroj.bindings.circuit.ExportCircuit',
         'org.zeroj.bindings.bundles.'+entry], folder/'compile.log')
    metadata = {'profile': name, 'capabilities': capabilities, 'apiVersion': 1,
                'graalvm': '25.3.4.1+1.1', 'binaryen': binaryen, 'classpathAndBuildSha256': inputs.hexdigest(),
                'worktreeDirty': bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()), 'seconds': time.perf_counter()-start,
                'zerojCommit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()}
    (folder/'build.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(name, 'built in', round(metadata['seconds'],2), 's', flush=True)
