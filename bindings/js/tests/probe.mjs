import { createRuntime } from '@zeroj/runtime';
import { bundle } from '../packages/bundle-probe/dist/index.js';
const runtime=createRuntime({bundles:[bundle]});
try { console.log(JSON.stringify(await runtime.call('probe','info',{}),null,2)); }
finally { await runtime.dispose(); }
