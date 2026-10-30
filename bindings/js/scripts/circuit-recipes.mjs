import fs from 'node:fs/promises';
import {symbolicExamples} from '../build/circuit-examples/symbolic-examples.js';
import {operations,underflow,widthOverflow} from '../build/circuit-examples/operation-examples.js';
const out=new URL('../../wasm/adapter-circuit/build/recipes/',import.meta.url);
await fs.mkdir(out,{recursive:true});
for(const definition of [...symbolicExamples,operations,underflow,widthOverflow])
  await fs.writeFile(new URL(definition.name+'.json',out),definition.recipe);
console.log('Exported public circuit recipes for JVM parity tests; no witness inputs.');
