/* Trusted worker bootstrap. Consume the exact bytes checked against the pinned descriptor. */
'use strict';
(async () => {
  const node = typeof process !== 'undefined' && !!process.versions?.node;
  let send, listen, openFile, vm, createRequire, fileURLToPath;
  if (node) {
    const { parentPort } = await import('node:worker_threads');
    ({open:openFile} = await import('node:fs/promises'));
    vm = await import('node:vm');
    ({createRequire} = await import('node:module'));
    ({fileURLToPath} = await import('node:url'));
    const {webcrypto} = await import('node:crypto');
    if(!globalThis.crypto) Object.defineProperty(globalThis,'crypto',{value:webcrypto});
    send = value => parentPort.postMessage(value);
    listen = handler => parentPort.on('message',handler);
  } else {
    send = value => self.postMessage(value);
    listen = handler => { self.onmessage = event => handler(event.data); };
  }
  let initialized=false, failed=false;
  async function checked(file) {
    if(!file || !/^[0-9a-f]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.bytes)
        || file.bytes<1 || file.bytes>128*1024*1024) throw Error();
    const url=new URL(file.url);
    let bytes;
    if(node) {
      if(url.protocol!=='file:') throw Error();
      const handle=await openFile(url,'r');
      try {
        const stat=await handle.stat();if(!stat.isFile() || stat.size!==file.bytes)throw Error();
        bytes=new Uint8Array(file.bytes);let offset=0;
        while(offset<bytes.length){const {bytesRead}=await handle.read(bytes,offset,bytes.length-offset,offset);if(!bytesRead)throw Error();offset+=bytesRead;}
        if((await handle.stat()).size!==file.bytes)throw Error();
      } finally {await handle.close();}
    } else {
      if(url.origin!==self.location.origin || !['https:','http:'].includes(url.protocol)) throw Error();
      const response=await fetch(url,{credentials:'omit',redirect:'error'});
      if(!response.ok) throw Error();
      if(!response.body) throw Error();
      const reader=response.body.getReader(),chunks=[];
      let total=0;
      try {
        while(true) {
          const chunk=await reader.read();if(chunk.done)break;
          total+=chunk.value.byteLength;
          if(total>file.bytes) {await reader.cancel();throw Error();}
          chunks.push(chunk.value);
        }
      } finally {reader.releaseLock();}
      if(total!==file.bytes)throw Error();
      bytes=new Uint8Array(total);let offset=0;
      for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    }
    if(bytes.byteLength!==file.bytes) throw Error();
    const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
    if(Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('')!==file.sha256) throw Error();
    return bytes;
  }
  listen(async data => {
    try {
      if(failed) return;
      if(data?.type==='init' && !initialized) {
        initialized=true;
        const descriptor=data.descriptor;
        if(descriptor.apiVersion!==1) throw Error();
        const [js,wasm]=await Promise.all([checked(descriptor.launcher),checked(descriptor.wasm)]);
        globalThis.ZEROJ_WASM_BYTES=wasm;
        globalThis.ZEROJ_EXPERIMENTAL_SECRETS=data.experimentalSecrets===true;
        await new Promise((resolve,reject)=>{
          globalThis.zerojReady=resolve;
          globalThis.zerojLoadFailed=()=>reject(Error());
          if(node) {
            globalThis.require=createRequire(descriptor.launcher.url);
            globalThis.__filename=fileURLToPath(descriptor.launcher.url);
            globalThis.__dirname=fileURLToPath(new URL('.',descriptor.launcher.url));
            try { vm.runInThisContext(new TextDecoder('utf-8',{fatal:true}).decode(js),{filename:globalThis.__filename}); }
            catch { reject(Error()); }
          } else {
            const url=URL.createObjectURL(new Blob([js],{type:'text/javascript'}));
            try { importScripts(url); } catch { reject(Error()); } finally { URL.revokeObjectURL(url); }
          }
        });
        const info=JSON.parse(String(globalThis.zerojCall(JSON.stringify({
          apiVersion:1,capability:'runtime',operation:'info',arguments:{}
        }))));
        if(!info.ok) throw Error();
        send({type:'ready',...info.value});
        return;
      }
      if(data?.type!=='call' || !initialized || typeof globalThis.zerojCall!=='function'
          || !Number.isSafeInteger(data.id) || typeof data.request!=='string'
          || data.request.length>1_048_576) throw Error();
      const result=JSON.parse(String(globalThis.zerojCall(data.request)));
      send({id:data.id,result});
    } catch { failed=true;send({type:'fatal'}); }
  });
})().catch(()=>{ /* Worker startup errors are bounded by the host startup deadline. */ });
