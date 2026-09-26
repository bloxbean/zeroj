// `npm run generate [outDir]` — write the AI artifacts to a directory for inspection without a
// full site build (default: .ai-preview/, which is git-ignored). The build does this itself.

import { resolve } from 'node:path';
import { WWW_ROOT } from '../site.config.mjs';
import { writeAiArtifacts } from './ai-artifacts.mjs';

const outDir = resolve(process.argv[2] ?? resolve(WWW_ROOT, '.ai-preview'));
await writeAiArtifacts(outDir, { info: (m) => console.log(m) });
