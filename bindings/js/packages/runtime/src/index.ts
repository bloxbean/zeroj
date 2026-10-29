/** Experimental Wasm runtime. Integrity pins assume the descriptor and host are trusted. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface BundleFile { readonly url: string | URL; readonly sha256: string; readonly bytes: number; }
export interface BundleDescriptor {
  readonly id: string; readonly apiVersion: 1; readonly capabilities: readonly string[];
  readonly launcher: BundleFile; readonly wasm: BundleFile;
}
export interface RuntimeOptions {
  readonly bundles: readonly BundleDescriptor[];
  readonly experimentalSecrets?: boolean;
  readonly timeoutMs?: number;
}
declare const handleBrand: unique symbol;
/** Worker-local object; cannot be serialized or reused with another runtime/image. */
export interface Handle<K extends string> { readonly kind: K; readonly [handleBrand]: true; }
export class ZeroJError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'ZeroJError'; }
}
type WorkerLike = {
  postMessage(value: unknown): void;
  terminate(): unknown;
  on?(event: string, callback: (...args: any[]) => void): unknown;
  addEventListener?(event: string, callback: (event: any) => void): void;
};
type Pending = { resolve(value: Json): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> };
type Slot = {
  worker?: WorkerLike; ready: Promise<void>; resolveReady(): void; rejectReady(error: Error): void;
  pending: Map<number, Pending>; failed?: ZeroJError; initTimer: ReturnType<typeof setTimeout>;
  admitted: number; termination?: Promise<unknown>;
};
function pin(file: BundleFile): {url:string;sha256:string;bytes:number} {
  const url = new URL(file.url).href;
  if (!/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.bytes)
      || file.bytes < 1 || file.bytes > 128 * 1024 * 1024) throw new ZeroJError('INVALID_DESCRIPTOR');
  return {url,sha256:file.sha256,bytes:file.bytes};
}
export class ZeroJRuntime {
  private readonly capabilities = new Map<string, BundleDescriptor>();
  private readonly slots = new Map<string, Slot>();
  private readonly timeout: number;
  private disposed = false;
  private nextId = 0;
  private readonly experimentalSecrets: boolean;
  private readonly handles = new WeakMap<object, {id:string;capability:string;kind:string}>();
  constructor(options: RuntimeOptions) {
    this.timeout = options.timeoutMs ?? 120_000;
    this.experimentalSecrets = options.experimentalSecrets === true;
    if (!Number.isSafeInteger(this.timeout) || this.timeout < 1 || this.timeout > 3_600_000)
      throw new ZeroJError('INVALID_TIMEOUT');
    const identities = new Set<string>();
    for (const original of options.bundles) {
      if (original.apiVersion !== 1 || !/^[a-z0-9-]{1,100}$/.test(original.id)
          || identities.has(original.id) || original.capabilities.length === 0) throw new ZeroJError('INVALID_DESCRIPTOR');
      identities.add(original.id);
      const descriptor = Object.freeze({...original, launcher:Object.freeze(pin(original.launcher)),
          wasm:Object.freeze(pin(original.wasm)), capabilities:Object.freeze([...original.capabilities])});
      for (const name of descriptor.capabilities) {
        if (!/^[a-z][a-z0-9-]{0,63}$/.test(name) || name === 'runtime' || this.capabilities.has(name))
          throw new ZeroJError('DUPLICATE_OR_INVALID_CAPABILITY');
        this.capabilities.set(name,descriptor);
      }
    }
  }
  private fail(slot: Slot, code: string): void {
    if (slot.failed) return;
    const error = new ZeroJError(code); slot.failed = error;
    clearTimeout(slot.initTimer);
    slot.rejectReady(error);
    for (const pending of slot.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    slot.pending.clear();
    if(slot.worker) slot.termination=Promise.resolve(slot.worker.terminate());
  }
  private slot(descriptor: BundleDescriptor): Slot {
    const found = this.slots.get(descriptor.id); if (found) return found;
    let resolveReady!: () => void, rejectReady!: (error: Error) => void;
    const ready = new Promise<void>((resolve,reject) => { resolveReady=resolve;rejectReady=reject; });
    // Every call observes readiness below; suppress an unhandled rejection during worker construction.
    void ready.catch(() => {});
    const slot: Slot = {ready,resolveReady,rejectReady,pending:new Map(),admitted:0,
      initTimer:setTimeout(()=>this.fail(slot,'STARTUP_TIMEOUT'),this.timeout)};
    this.slots.set(descriptor.id,slot);
    void (async () => {
      try {
        let worker: WorkerLike;
        if (typeof process !== 'undefined' && process.versions?.node) {
          const { Worker } = await import('node:worker_threads');
          if(this.disposed || slot.failed) return;
          worker = new Worker(new URL('./worker.js',import.meta.url), {name:'zeroj-'+descriptor.id});
        } else {
          worker = new Worker(new URL('./worker.js',import.meta.url), {name:'zeroj-'+descriptor.id});
        }
        slot.worker=worker;
        if(this.disposed || slot.failed) { void worker.terminate(); return; }
        const message=(data:any) => {
          if(slot.failed) return;
          if(data?.type==='ready') {
            if(data.apiVersion!==1 || !Array.isArray(data.capabilities)
                || descriptor.capabilities.length!==data.capabilities.length
                || !descriptor.capabilities.every(c=>data.capabilities.includes(c))) {
              this.fail(slot,'CAPABILITY_MISMATCH');return;
            }
            clearTimeout(slot.initTimer);slot.resolveReady();return;
          }
          if(data?.type==='fatal') { this.fail(slot,'BUNDLE_LOAD_FAILED');return; }
          const pending=slot.pending.get(data?.id);
          if(!pending) { this.fail(slot,'INVALID_RESPONSE'); return; }
          slot.pending.delete(data.id);clearTimeout(pending.timer);
          if(data.result?.ok===true) pending.resolve(data.result.value as Json);
          else if(data.result?.ok===false && typeof data.result.error?.code==='string')
            pending.reject(new ZeroJError(data.result.error.code));
          else { pending.reject(new ZeroJError('INVALID_RESPONSE'));this.fail(slot,'INVALID_RESPONSE'); }
        };
        if(worker.on) {
          worker.on('message',message);
          worker.on('error',()=>this.fail(slot,'WORKER_FAILED'));
          worker.on('exit',()=>this.fail(slot,'WORKER_EXITED'));
        } else {
          worker.addEventListener!('message',event=>message(event.data));
          worker.addEventListener!('error',()=>this.fail(slot,'WORKER_FAILED'));
          worker.addEventListener!('messageerror',()=>this.fail(slot,'INVALID_RESPONSE'));
        }
        worker.postMessage({type:'init',descriptor,experimentalSecrets:this.experimentalSecrets});
      } catch { this.fail(slot,'WORKER_START_FAILED'); }
    })();
    return slot;
  }
  async call<T extends Json = Json>(capability: string, operation: string, args: { [key:string]:Json }): Promise<T> {
    return this.invoke<T>(capability,operation,args,false);
  }
  private async invoke<T extends Json>(capability: string, operation: string, args: { [key:string]:Json }, control: boolean): Promise<T> {
    if(this.disposed) throw new ZeroJError('DISPOSED');
    const descriptor=this.capabilities.get(capability);
    if(!descriptor) throw new ZeroJError('UNSUPPORTED_CAPABILITY');
    let request: string;
    try { request=JSON.stringify({apiVersion:1,capability:control?'runtime':capability,operation,arguments:args}); }
    catch { throw new ZeroJError('INVALID_REQUEST'); }
    if(request.length>1_048_576) throw new ZeroJError('REQUEST_TOO_LARGE');
    const slot=this.slot(descriptor);
    if(slot.admitted>=64) throw new ZeroJError('QUEUE_LIMIT');
    slot.admitted++;
    try {
      await slot.ready;
      if(this.disposed) throw new ZeroJError('DISPOSED');
      if(slot.failed) throw slot.failed;
      return await new Promise<T>((resolve,reject)=>{
      const id=++this.nextId;
      const timer=setTimeout(()=>this.fail(slot,'CALL_TIMEOUT'),this.timeout);
      slot.pending.set(id,{resolve:value=>resolve(value as T),reject,timer});
      try { slot.worker!.postMessage({type:'call',id,request}); }
      catch { this.fail(slot,'WORKER_FAILED'); }
      });
    } finally {slot.admitted--;}
  }
  /** @internal Used by typed adapters after receiving a Java-created handle. */
  retainHandle<K extends string>(kind: K, capability: string, id: string): Handle<K> {
    if(this.disposed || !this.capabilities.has(capability) || !/^h[1-9][0-9]*$/.test(id))
      throw new ZeroJError('INVALID_HANDLE');
    const handle=Object.freeze({kind}) as Handle<K>;
    this.handles.set(handle,{id,capability,kind});return handle;
  }
  /** @internal Reject foreign/released handles and handles from another physical image. */
  handleId<K extends string>(handle: Handle<K>, kind: K, capability: string): string {
    const entry=this.handles.get(handle);
    const owner=entry && this.capabilities.get(entry.capability), target=this.capabilities.get(capability);
    if(this.disposed || !entry || entry.kind!==kind || !owner || !target || owner.id!==target.id
        || this.slots.get(owner.id)?.failed) throw new ZeroJError('INVALID_HANDLE');
    return entry.id;
  }
  async release(handle: Handle<string>): Promise<void> {
    const entry=this.handles.get(handle);
    if(!entry) throw new ZeroJError('INVALID_HANDLE');
    const id=this.handleId(handle,entry.kind,entry.capability);
    await this.invoke(entry.capability,'release',{handle:id},true);
    this.handles.delete(handle);
  }
  async preload(capability: string): Promise<void> {
    if(this.disposed) throw new ZeroJError('DISPOSED');
    const descriptor=this.capabilities.get(capability);
    if(!descriptor) throw new ZeroJError('UNSUPPORTED_CAPABILITY');
    await this.slot(descriptor).ready;
  }
  /** Termination invalidates every handle and pending operation; it does not prove secret erasure. */
  async dispose(): Promise<void> {
    this.disposed=true;
    for(const slot of this.slots.values()) this.fail(slot,'DISPOSED');
    await Promise.allSettled([...this.slots.values()].map(slot=>slot.termination));
    this.slots.clear();
  }
}
export function createRuntime(options: RuntimeOptions): ZeroJRuntime { return new ZeroJRuntime(options); }
export function bytesToHex(bytes: Uint8Array, maxBytes=262_144): string {
  if(!(bytes instanceof Uint8Array) || bytes.byteLength>maxBytes) throw new ZeroJError('INVALID_BYTES');
  return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
}
export function hexToBytes(hex: string): Uint8Array {
  if(typeof hex!=='string' || !/^(?:[0-9a-f]{2})*$/.test(hex) || hex.length>524_288)
    throw new ZeroJError('INVALID_BYTES');
  return Uint8Array.from(hex.match(/../g) ?? [],h=>parseInt(h,16));
}
export function scalarToString(value: bigint, modulus: bigint): string {
  if(typeof value!=='bigint' || value<0n || value>=modulus) throw new ZeroJError('INVALID_SCALAR');
  return value.toString();
}
