import fs from 'node:fs/promises';
import {runScenario} from '../shared/scenarios.js';
const build=new URL('../../build/',import.meta.url);
const read=async name=>new Uint8Array(await fs.readFile(new URL(name,build)));
const json=async name=>JSON.parse(new TextDecoder().decode(await read(name)));
for(const name of ['pedersen','bbs','groth16','elgamal','threshold','notes']) {
 console.log(name,await runScenario(name,json,read));
}
