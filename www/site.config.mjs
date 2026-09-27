// Single source of truth for site-wide values used by astro.config.mjs, the landing page,
// the AI artifact generator and the build checks.
//
// Versions are read from the ZeroJ build at build time, so the docs never drift from the code:
//   ZEROJ_VERSION  gradle.properties `version` with any -SNAPSHOT suffix removed
//   JULC_VERSION   zeroj-onchain-julc/build.gradle `julcVersion`
//   CCL_VERSION    root build.gradle `ext.cclVersion`
// Markdown/MDX pages reference them as %ZEROJ_VERSION%, %JULC_VERSION% and %CCL_VERSION%;
// scripts/remark-versions.mjs substitutes them in rendered pages and the AI exports.

import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// This module is also bundled into Astro's prerender chunks (dist/.prerender/…), so locate the
// site root by walking up to astro.config.mjs rather than trusting this file's own location.
function findWwwRoot() {
  for (const start of [dirname(fileURLToPath(import.meta.url)), process.cwd()]) {
    let dir = start;
    for (let i = 0; i < 8; i++) {
      if (existsSync(resolve(dir, 'astro.config.mjs')) && existsSync(resolve(dir, 'site.config.mjs'))) return dir;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  throw new Error('site.config.mjs: cannot locate the www/ directory');
}

export const WWW_ROOT = findWwwRoot();
export const REPO_ROOT = resolve(WWW_ROOT, '..');
export const CONTENT_ROOT = resolve(WWW_ROOT, 'src/content/docs');

// Canonical public URL of the site. Change here (and in public/CNAME) if the domain changes.
export const SITE_URL = 'https://zeroj.dev';
export const SITE_DOMAIN = new URL(SITE_URL).hostname;

export const REPO_URL = 'https://github.com/bloxbean/zeroj';
export const USECASES_URL = 'https://github.com/bloxbean/zeroj-usecases';

function read(rel) {
  return readFileSync(resolve(REPO_ROOT, rel), 'utf8');
}

function match(text, pattern, what) {
  const found = text.match(pattern)?.[1]?.trim();
  if (!found) throw new Error(`site.config.mjs: could not read ${what}`);
  return found;
}

export const ZEROJ_DEV_VERSION = match(read('gradle.properties'), /^version\s*=\s*(\S+)/m, 'ZeroJ version');
export const ZEROJ_VERSION = ZEROJ_DEV_VERSION.replace(/-SNAPSHOT$/, '');
export const JULC_VERSION = match(
  read('zeroj-onchain-julc/build.gradle'),
  /julcVersion\s*=\s*'([^']+)'/,
  'JuLC version',
);
export const CCL_VERSION = match(read('build.gradle'), /ext\.cclVersion\s*=\s*'([^']+)'/, 'CCL version');

export const VERSION_TOKENS = {
  '%ZEROJ_VERSION%': ZEROJ_VERSION,
  '%JULC_VERSION%': JULC_VERSION,
  '%CCL_VERSION%': CCL_VERSION,
  '%SITE_URL%': SITE_URL,
};

export function replaceVersionTokens(text) {
  let out = text;
  for (const [token, value] of Object.entries(VERSION_TOKENS)) out = out.replaceAll(token, value);
  return out;
}

export function sourceRevision() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}
