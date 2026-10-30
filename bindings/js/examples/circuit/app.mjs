import {scenario} from './scenarios.mjs';
const load=async(name,kind)=>{const r=await fetch('../../build/circuit/'+name,{redirect:'error'});if(!r.ok)throw Error('FIXTURE_LOAD_FAILED');return kind==='text'?r.text():r.arrayBuffer();};
for(const button of document.querySelectorAll('button[data-name]'))button.addEventListener('click',async()=>{
  const name=button.dataset.name,target=document.getElementById(name);
  for(const b of document.querySelectorAll('button'))b.disabled=true;
  target.textContent='Compiling in the Wasm worker…';delete target.dataset.status;
  try{
    const {proof,verificationKey,...result}=await scenario(name,load);
    for(const k of Object.keys(result))if(k.endsWith('Ms'))result[k]=Math.round(result[k]*10)/10;
    target.textContent=JSON.stringify(result,null,2);target.dataset.status='passed';
  }catch(error){target.textContent='Example failed: '+(error.code??error.message);target.dataset.status='failed';}
  finally{for(const b of document.querySelectorAll('button'))b.disabled=false;}
});
