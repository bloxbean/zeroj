// Public local artifact census only. This is not a cryptographic zkey parser or admission path.
import fs from 'node:fs/promises';
import {gzipSync,brotliCompressSync,constants} from 'node:zlib';
const root=new URL('../build/circuit-large/',import.meta.url),rows=[];
for(const depth of [8,16,32]){
 const key=await fs.readFile(new URL('merkle_d'+depth+'/key.zkey',root));
 if(key.length>33554432||key.toString('ascii',0,4)!=='zkey')throw Error('Expected bounded generated fixture');
 const row={depth,keyBytes:key.length,gzipBytes:gzipSync(key,{level:9}).length,
  brotliBytes:brotliCompressSync(key,{params:{[constants.BROTLI_PARAM_QUALITY]:9}}).length,querySections:{}};
 let offset=12;
 for(let i=0;i<key.readUInt32LE(8);i++){
  const id=key.readUInt32LE(offset),bytes=Number(key.readBigUInt64LE(offset+4));offset+=12;
  if([5,6,7,8,9].includes(id)){
   const stride=id===7?192:96;let allZeroEntries=0;
   for(let j=offset;j<offset+bytes;j+=stride)if(key.subarray(j,j+stride).every(b=>b===0))allZeroEntries++;
   row.querySections[id]={bytes,entries:bytes/stride,allZeroEntries};
  }
  offset+=bytes;
 }
 if(offset!==key.length)throw Error('Unexpected fixture sections');rows.push(row);
}
await fs.writeFile(new URL('query-census.json',root),JSON.stringify(rows,null,2));
console.log(JSON.stringify(rows.map(({querySections,...r})=>r),null,2));
