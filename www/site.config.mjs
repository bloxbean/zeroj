// Single source of truth for site-wide values used by astro.config.mjs, the landing page,
// the AI artifact generator and the build checks.
//
// Versions come from www/release.json, which maintainers update after each release is on Maven
// Central, so the docs only advertise what users can download (main's gradle.properties is usually
// the NEXT, unpublished version):
//   ZEROJ_VERSION   release.json `zeroj`   the published ZeroJ version the docs install
//   JULC_VERSION    release.json `julc`    the JuLC version that release was built with
//   CCL_VERSION     release.json `ccl`     the Cardano Client Lib version that release was built with
//   ZEROJ_RELEASED  release.json `released` false until `zeroj` is on Maven Central (pages then show
//                   a "not released yet" note; scripts/check-release.mjs skips the Central check)
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

// The version main is building (usually the next release, with -SNAPSHOT). Recorded in the AI
// manifest only; the docs never tell users to install it.
export const ZEROJ_DEV_VERSION = match(read('gradle.properties'), /^version\s*=\s*(\S+)/m, 'ZeroJ version');

export const RELEASE = readRelease();
export const ZEROJ_VERSION = RELEASE.zeroj;
export const JULC_VERSION = RELEASE.julc;
export const CCL_VERSION = RELEASE.ccl;
export const ZEROJ_RELEASED = RELEASE.released;

function readRelease() {
  const release = JSON.parse(readFileSync(resolve(WWW_ROOT, 'release.json'), 'utf8'));
  for (const key of ['zeroj', 'julc', 'ccl']) {
    if (typeof release[key] !== 'string' || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(release[key])) {
      throw new Error(`release.json: "${key}" must be a release version like 0.1.0-pre12, got ${JSON.stringify(release[key])}`);
    }
    if (release[key].endsWith('-SNAPSHOT')) throw new Error(`release.json: "${key}" must not be a SNAPSHOT`);
  }
  if (typeof release.released !== 'boolean') throw new Error('release.json: "released" must be true or false');
  return release;
}

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
