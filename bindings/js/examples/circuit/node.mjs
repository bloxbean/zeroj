import fs from 'node:fs/promises';
import {scenario} from './scenarios.mjs';
const load=(name,kind)=>fs.readFile(new URL('../../build/circuit/'+name,import.meta.url),kind==='text'?'utf8':undefined);
for(const name of process.argv.slice(2).length?process.argv.slice(2):['age_check','poseidon_opening']){
  const {proof,verificationKey,...result}=await scenario(name,load);
  console.log(JSON.stringify(result,null,2));
}
