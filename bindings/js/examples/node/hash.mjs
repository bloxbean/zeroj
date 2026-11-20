import {createRuntime,bytesToHex} from '@zeroj/runtime';
import {createHash} from '@zeroj/hash';
import {bundle} from '../../packages/bundle-hash/dist/index.js';
const runtime=createRuntime({bundles:[bundle]});
try {
  const hash=createHash(runtime,{shaBackend:'wasm'});
  const input=new TextEncoder().encode('Hello from ZeroJ');
  console.log('SHA-256',bytesToHex(await hash.sha256(input)));
  console.log('SHA-512',bytesToHex(await hash.sha512(input)));
  console.log('BLAKE2b-256',bytesToHex(await hash.blake2b(input)));
} finally {await runtime.dispose();}
