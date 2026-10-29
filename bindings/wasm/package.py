#!/usr/bin/env python3
"""Package checked Web Image bytes as opt-in npm assets; never publish."""
from pathlib import Path
import argparse, gzip, hashlib, json, shutil, subprocess
ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT/'bindings/wasm'
parser=argparse.ArgumentParser()
parser.add_argument('profiles',nargs='+')
args=parser.parse_args()
version='0.1.0-experimental.1'
sizes={}
for name in args.profiles:
    folder=HERE/'build/images'/name
    meta=json.loads((folder/'build.json').read_text())
    launcher=(folder/'engine.js').read_text()
    anchor='const file = await runtime.fetchData(wasmPath);'
    if launcher.count(anchor)!=1: raise SystemExit('Pinned launcher fetch anchor changed')
    launcher=launcher.replace(anchor,'''const file = globalThis.ZEROJ_WASM_BYTES;
    if (!(file instanceof Uint8Array)) throw new Error("Verified Wasm bytes required");''')
    anchor='const config = new GraalVM.Config();'
    if launcher.count(anchor)!=1: raise SystemExit('Pinned launcher configuration anchor changed')
    launcher=launcher.replace(anchor,anchor+'\nconfig.wasm_path="verified-by-zeroj-runtime";')
    files={'launcher':launcher.encode(),'wasm':(folder/'engine.js.wasm').read_bytes()}
    identity=name+'-'+hashlib.sha256(files['launcher']+files['wasm']).hexdigest()[:24]
    package=ROOT/'bindings/js/packages'/('bundle-'+name)
    assets=package/'assets';dist=package/'dist'
    assets.mkdir(parents=True,exist_ok=True);dist.mkdir(exist_ok=True)
    info={'id':identity,'apiVersion':1,'capabilities':meta['capabilities']}
    for kind,data in files.items():
        filename='engine.js' if kind=='launcher' else 'engine.wasm'
        (assets/filename).write_bytes(data)
        info[kind]={'url':'../assets/'+filename,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        br=subprocess.check_output(['node','--input-type=module','-e',
          "import z from 'node:zlib';import fs from 'node:fs';process.stdout.write(z.brotliCompressSync(fs.readFileSync(0),{params:{[z.constants.BROTLI_PARAM_QUALITY]:11}}));"],input=data)
        info[kind]['gzipBytes']=len(gzip.compress(data,compresslevel=9,mtime=0))
        info[kind]['brotliBytes']=len(br)
    (assets/'manifest.json').write_text(json.dumps({**info,'build':meta},indent=2)+'\n')
    text='const descriptor = '+json.dumps(info,indent=2)+';\n'
    text+='for (const key of ["launcher","wasm"]) descriptor[key].url = new URL(descriptor[key].url, import.meta.url).href;\n'
    text+='export const bundle = Object.freeze(descriptor);\n'
    (dist/'index.js').write_text(text)
    (dist/'index.d.ts').write_text('import type { BundleDescriptor } from "@zeroj/runtime";\nexport declare const bundle: BundleDescriptor;\n')
    (package/'package.json').write_text(json.dumps({
      'name':'@zeroj/bundle-'+name,'version':version,'private':name in ('probe','unprotected'),'type':'module',
      'description':'Experimental ZeroJ precompiled '+name+' Web Image bundle',
      'license':'MIT','main':'./dist/index.js','types':'./dist/index.d.ts',
      'exports':{'.':{'types':'./dist/index.d.ts','import':'./dist/index.js'}},
      'files':['dist','assets','README.md','LICENSE','NOTICE'],
      'dependencies':{'@zeroj/runtime':version},'publishConfig':{'access':'public'}},indent=2)+'\n')
    (package/'README.md').write_text('# @zeroj/bundle-'+name+'\n\nExperimental precompiled image. Register its bundle descriptor with createRuntime.\nImporting the descriptor loads no Wasm. Generated files are included in npm tarballs, not Git.\nThe launcher preserves its upstream license headers. Consult ADR-0057 and bindings documentation.\n')
    for filename in ['LICENSE','NOTICE']: shutil.copyfile(ROOT/filename,package/filename)
    sizes[name]={**info,'build':meta}
out=HERE/'build/package-results.json';out.write_text(json.dumps(sizes,indent=2)+'\n')
print(json.dumps({name:{kind:entry[kind]['bytes'] for kind in ['launcher','wasm']} for name,entry in sizes.items()},indent=2))
