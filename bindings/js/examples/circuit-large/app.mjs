import {largeResearch} from '../circuit/large-research.mjs';
const box=document.getElementById('result'),cancel=document.getElementById('cancel');let controller;
const load=async(name,kind)=>{const r=await fetch('/build/circuit-large/'+name,{redirect:'error'});if(!r.ok)throw Error('BUILD_RESEARCH_FIXTURES_FIRST');return kind==='text'?r.text():r.arrayBuffer();};
cancel.addEventListener('click',()=>controller?.abort());
for(const button of document.querySelectorAll('button[data-depth]'))button.addEventListener('click',async()=>{
 for(const b of document.querySelectorAll('button[data-depth]'))b.disabled=true;
 controller=new AbortController();cancel.disabled=false;delete box.dataset.status;document.getElementById('details').hidden=true;
 try{
  const {proof,...result}=await largeResearch('merkle_d'+button.dataset.depth,load,{signal:controller.signal,onPhase:p=>{box.textContent=p+'…';}});
  box.textContent=JSON.stringify({name:result.name,keyBytes:result.keyBytes,
   constraints:result.description.constraints,wires:result.description.wires,timingsMs:result.timingsMs,
   warmProofMs:result.warmProofMs,invalidPathRejected:result.invalidPathRejected,
   changedRootRejected:result.changedRootRejected,snarkjsAccepted:result.snarkjsAccepted},null,2);
  document.getElementById('full-result').textContent=JSON.stringify(result,null,2);document.getElementById('details').hidden=false;box.dataset.status='passed';
 }catch(e){box.textContent='Experiment stopped: '+(e.code??e.message);box.dataset.status='stopped';}
 finally{controller=undefined;cancel.disabled=true;for(const b of document.querySelectorAll('button[data-depth]'))b.disabled=false;}
});
