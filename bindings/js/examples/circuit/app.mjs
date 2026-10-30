import {scenario} from './scenarios.mjs';
const load=async(name,kind)=>{const r=await fetch('../../build/circuit/'+name,{redirect:'error'});if(!r.ok)throw Error('FIXTURE_LOAD_FAILED');return kind==='text'?r.text():r.arrayBuffer();};
for(const button of document.querySelectorAll('button[data-name]'))button.addEventListener('click',async()=>{
  const name=button.dataset.name,target=document.getElementById(name);
  for(const b of document.querySelectorAll('button'))b.disabled=true;
  target.textContent='Compiling in the Wasm worker…';delete target.dataset.status;
  try{
    const {proof,verificationKey,...result}=await scenario(name,load);
    for(const k of Object.keys(result))if(k.endsWith('Ms'))result[k]=Math.round(result[k]*10)/10;
    const fields=['name','authoring','constraints','wires','valid','proofGenerated','proofLimit','expandMs','compileMs','witnessMs','constraintCheckMs','keyLoadMs','proveAndSelfVerifyMs','totalMs','tamperedAccepted','snarkjsAccepted','hostDigestMatches'];
    target.textContent=JSON.stringify(Object.fromEntries(fields.filter(k=>k in result).map(k=>[k,result[k]])),null,2);target.dataset.status='passed';
    let details=target.nextElementSibling;
    if(!details?.classList.contains('artifact-details')){
      details=document.createElement('details');details.className='artifact-details';
      const summary=document.createElement('summary');summary.textContent='Artifact identity and resource details';
      details.append(summary,document.createElement('pre'));target.insertAdjacentElement('afterend',details);
    }
    details.querySelector('pre').textContent=JSON.stringify(result,null,2);
  }catch(error){target.textContent='Example failed: '+(error.code??error.message);target.dataset.status='failed';}
  finally{for(const b of document.querySelectorAll('button'))b.disabled=false;}
});
