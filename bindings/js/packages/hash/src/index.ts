import { type ZeroJRuntime, ZeroJError, bytesToHex, hexToBytes } from '@zeroj/runtime';
export interface HashOptions { shaBackend?: 'webcrypto' | 'wasm'; }
export function createHash(runtime?: ZeroJRuntime, options: HashOptions = {}) {
  if(options.shaBackend!==undefined && !['webcrypto','wasm'].includes(options.shaBackend))
    throw new ZeroJError('INVALID_BACKEND');
  const wasm = async (operation:string,data:Uint8Array,extra:Record<string,number>={}) => {
    if(!runtime) throw new ZeroJError('RUNTIME_REQUIRED');
    const result=await runtime.call<{digest:string}>('hash',operation,{data:bytesToHex(data),...extra});
    return hexToBytes(result.digest);
  };
  const sha = async (operation:'sha256'|'sha512',data:Uint8Array) => {
    if(options.shaBackend==='wasm') return wasm(operation,data);
    bytesToHex(data); // Same bounded byte contract across backends.
    if(!globalThis.crypto?.subtle) throw new ZeroJError('WEBCRYPTO_UNAVAILABLE');
    return new Uint8Array(await crypto.subtle.digest(operation==='sha256'?'SHA-256':'SHA-512',
      Uint8Array.from(data)));
  };
  return Object.freeze({
    sha256:(data:Uint8Array)=>sha('sha256',data),
    sha512:(data:Uint8Array)=>sha('sha512',data),
    blake2b:(data:Uint8Array,outputBytes=32)=>{
      if(!Number.isInteger(outputBytes)||outputBytes<1||outputBytes>64) throw new ZeroJError('INVALID_DIGEST_LENGTH');
      return wasm('blake2b',data,{outputBytes});
    },
  });
}
