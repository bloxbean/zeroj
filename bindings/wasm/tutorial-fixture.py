#!/usr/bin/env python3
"""Generate public tutorial fixtures with snarkjs 0.7.6. DEVELOPMENT SETUP ONLY.
No setup code is linked into a consumer image. Output stays under ignored build/.
"""
from pathlib import Path
import hashlib,json,os,secrets,subprocess
ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'bindings/wasm'
OUT=ROOT/'bindings/js/build/tutorial';OUT.mkdir(parents=True,exist_ok=True)
java=Path(os.environ['JAVA_HOME'])/'bin/java'
cp=(HERE/'bundles/build/classpath.txt').read_text()
subprocess.run([str(java),'-cp',cp,'org.zeroj.bindings.bundles.ExportTutorial',str(OUT)],check=True,cwd=ROOT)
cli=ROOT/'bindings/js/node_modules/snarkjs/build/cli.cjs'
def run(*args):
 with (OUT/'setup.log').open('a') as log:
  subprocess.run(['node',str(cli),*args],check=True,cwd=OUT,stdout=log,stderr=subprocess.STDOUT)
run('powersoftau','new','bls12-381','4','pot0.ptau')
run('powersoftau','contribute','pot0.ptau','pot1.ptau','--name=zeroj-browser-development','-e='+secrets.token_hex(64))
run('powersoftau','prepare','phase2','pot1.ptau','pot_final.ptau')
run('groth16','setup','circuit.r1cs','pot_final.ptau','key0.zkey')
run('zkey','contribute','key0.zkey','key.zkey','--name=zeroj-browser-development','-e='+secrets.token_hex(64))
run('zkey','verify','circuit.r1cs','pot_final.ptau','key.zkey')
run('zkey','export','verificationkey','key.zkey','vk.json')
metadata=json.loads((OUT/'circuit.json').read_text())
metadata.update({'developmentOnly':True,'snarkjs':'0.7.6','sha256':hashlib.sha256((OUT/'key.zkey').read_bytes()).hexdigest()})
(OUT/'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
# Intermediate ceremony artifacts are not needed by the example.
for name in ['pot0.ptau','pot1.ptau','pot_final.ptau','key0.zkey']: (OUT/name).unlink()
print('Generated development-only tutorial key:',metadata['sha256'])
