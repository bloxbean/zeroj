import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
for (const name of ['runtime','hash','pedersen','bbs','groth16-verifier','groth16-prover','elgamal','threshold','confidential-notes']) {
  const result = spawnSync(process.execPath,[path.join(root,'node_modules/typescript/bin/tsc'),'-p',path.join(root,'packages',name)],{stdio:'inherit'});
  if(result.status !== 0) process.exit(result.status ?? 1);
  for(const file of ['LICENSE','NOTICE']) copyFileSync(path.join(root,'../..',file),path.join(root,'packages',name,file));
}
copyFileSync(path.join(root,'packages/runtime/src/worker.js'),path.join(root,'packages/runtime/dist/worker.js'));
