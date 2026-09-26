// Astro integration that publishes the AI artifacts built by ai-artifacts.mjs.
//
// - `astro build`: writes them into the build output (dist/) next to the static site.
// - `astro dev`:   serves them from memory, regenerated per request, so /llms.txt,
//                  /ai/pages/<slug>.md, /ai/starter-pack.md, /ai/catalog.json … reflect doc edits
//                  without a restart and without writing generated files into public/.

import { fileURLToPath } from 'node:url';
import { buildAiArtifacts, writeAiArtifacts } from './ai-artifacts.mjs';

const CONTENT_TYPES = {
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

function servedPath(url) {
  const path = decodeURIComponent((url || '').split('?')[0]);
  if (path === '/llms.txt' || path === '/llms-full.txt') return path.slice(1);
  if (path.startsWith('/ai/') && /\.(md|json)$/.test(path)) return path.slice(1);
  return null;
}

export default function aiArtifacts() {
  return {
    name: 'zeroj-ai-artifacts',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        await writeAiArtifacts(fileURLToPath(dir), logger);
      },
      'astro:server:setup': async ({ server, logger }) => {
        server.middlewares.use(async (req, res, next) => {
          const rel = servedPath(req.url);
          if (!rel) return next();
          try {
            const files = await buildAiArtifacts();
            const body = files.get(rel);
            if (body === undefined) return next();
            const ext = rel.slice(rel.lastIndexOf('.'));
            res.statusCode = 200;
            res.setHeader('Content-Type', CONTENT_TYPES[ext] ?? 'text/plain; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.end(body);
          } catch (err) {
            logger.error(`[ai] failed to generate ${rel}: ${err.stack || err.message}`);
            res.statusCode = 500;
            res.end(`AI artifact generation failed: ${err.message}`);
          }
        });
        logger.info('[ai] serving /llms.txt, /llms-full.txt and /ai/* from the dev server');
      },
    },
  };
}
