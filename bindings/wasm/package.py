#!/usr/bin/env python3
"""Package checked Web Image bytes as opt-in npm assets; never publish."""
from pathlib import Path
import argparse, gzip, hashlib, json, shutil, subprocess, os, zipfile
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
    anchor='GraalVM.run(load_cmd_args(),config).catch(e => { console.error(e); throw e; });'
    if launcher.count(anchor)!=1: raise SystemExit('Pinned launcher failure anchor changed')
    launcher=launcher.replace(anchor,'GraalVM.run(load_cmd_args(),config).catch(() => globalThis.zerojLoadFailed());')
    launcher='/* ZeroJ modifications, 2026-10-30: verified byte injection, explicit Wasm path, bounded startup error hook. Original copyright and license headers preserved below. */\n'+launcher
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
    text+='descriptor.launcher.url = new URL("../assets/engine.js", import.meta.url).href;\n'
    text+='descriptor.wasm.url = new URL("../assets/engine.wasm", import.meta.url).href;\n'
    text+='export const bundle = Object.freeze(descriptor);\n'
    (dist/'index.js').write_text(text)
    (dist/'index.d.ts').write_text('import type { BundleDescriptor } from "@zeroj/runtime";\nexport declare const bundle: BundleDescriptor;\n')
    (package/'package.json').write_text(json.dumps({
      'name':'@zeroj/bundle-'+name,'version':version,'private':True,'type':'module',
      'description':'Experimental ZeroJ precompiled '+name+' Web Image bundle',
      'license':'SEE LICENSE IN DISTRIBUTION.md','main':'./dist/index.js','types':'./dist/index.d.ts',
      'exports':{'.':{'types':'./dist/index.d.ts','import':'./dist/index.js'}},
      'files':['dist','assets','README.md','LICENSE','NOTICE','DISTRIBUTION.md','third-party'],
      'dependencies':{'@zeroj/runtime':version},'publishConfig':{'access':'public'}},indent=2)+'\n')
    (package/'README.md').write_text('# @zeroj/bundle-'+name+'\n\nExperimental precompiled image. Register its bundle descriptor with createRuntime.\nImporting the descriptor loads no Wasm. Generated files are included in npm tarballs, not Git.\nThe launcher preserves its upstream license headers. Consult ADR-0057 and bindings documentation.\n')
    for filename in ['LICENSE','NOTICE']: shutil.copyfile(ROOT/filename,package/filename)
    shutil.copyfile(ROOT/'bindings/DISTRIBUTION.md',package/'DISTRIBUTION.md')
    # Local tarball inventory, not a claim that every compiler component is linked into every image.
    home=Path(os.environ.get('GRAALVM_HOME',os.environ.get('JAVA_HOME','')))
    if not (home/'LICENSE.txt').is_file(): raise SystemExit('Set GRAALVM_HOME when packaging to preserve compiler notices')
    legal=package/'third-party';legal.mkdir(exist_ok=True)
    shutil.copyfile(home/'LICENSE.txt',legal/'Oracle-GraalVM-GFTC.txt')
    # GraalVM notices include read-only files. Recreate this generated subtree so
    # a second packaging run need not overwrite those files in place.
    legal_tree=legal/'graalvm-legal'
    if legal_tree.exists(): shutil.rmtree(legal_tree)
    shutil.copytree(home/'legal',legal_tree)
    shutil.copyfile(ROOT/'licenses/Apache-2.0.txt',legal/'Apache-2.0.txt')
    (legal/'graalvm-release.txt').write_text((home/'release').read_text())
    for entry in (HERE/'bundles/build/classpath.txt').read_text().split(os.pathsep):
        jar=Path(entry)
        if not jar.is_file() or jar.suffix!='.jar': continue
        with zipfile.ZipFile(jar) as archive:
            for path in archive.namelist():
                if path.endswith('/') or not path.startswith('META-INF/'): continue
                leaf=path.rsplit('/',1)[-1]
                if not leaf.upper().startswith(('LICENSE','NOTICE','COPYRIGHT')): continue
                target=legal/'dependencies'/jar.name/leaf
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(path))
    entries={str(path.relative_to(legal)):hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(legal.rglob('*')) if path.is_file() and path.name!='NOTICE'}
    (legal/'NOTICE').write_text('Locally copied, unchanged notices from Oracle GraalVM 25.3.4.1+1.1 and the exact build classpath.\n'
        +'Authors, copyright holders and terms are retained in each file. Sources: https://www.graalvm.org/ and Maven Central.\n'
        +'Generated only for local review tarballs; nothing is published by this build. See DISTRIBUTION.md.\n'
        +'The inventory is conservative and is not a linked-code attribution decision. SHA-256 per file:\n'+json.dumps(entries,indent=2)+'\n')
    sizes[name]={**info,'build':meta}
out=HERE/'build/package-results.json';out.write_text(json.dumps(sizes,indent=2)+'\n')
print(json.dumps({name:{kind:entry[kind]['bytes'] for kind in ['launcher','wasm']} for name,entry in sizes.items()},indent=2))
