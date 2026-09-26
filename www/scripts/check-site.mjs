// Post-build verification of dist/ (run by `npm run build`). Fails the build on:
//   - broken internal links, assets or #anchors
//   - unreplaced %VERSION% tokens in any published file
//   - a docs page without its /ai/pages/<slug>.md twin, or an llms.txt link to a missing file
//   - manifest checksums that don't match the published bytes
//   - links to github.com/bloxbean/zeroj/{blob,tree}/main/<path> whose <path> doesn't exist in this
//     checkout (and the same for zeroj-usecases when ZEROJ_USECASES_DIR points at a checkout)

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { REPO_ROOT, SITE_URL, VERSION_TOKENS, WWW_ROOT } from '../site.config.mjs';

const dist = resolve(WWW_ROOT, 'dist');
const failures = [];
const fail = (msg) => failures.push(msg);

async function walk(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name);
    out.push(...(e.isDirectory() ? await walk(p) : [p]));
  }
  return out;
}

const all = await walk(dist);
const rel = (f) => f.slice(dist.length);
const htmlFiles = all.filter((f) => f.endsWith('.html'));
const html = new Map(await Promise.all(htmlFiles.map(async (f) => [f, await readFile(f, 'utf8')])));
const ids = new Map([...html].map(([f, h]) => [f, new Set([...h.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]))]));

// ---- internal links, assets and anchors
for (const [file, page] of html) {
  for (const m of page.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    const value = m[1].replaceAll('&amp;', '&');
    if (value.startsWith('#')) {
      const id = decodeURIComponent(value.slice(1));
      if (id && !ids.get(file).has(id)) fail(`Missing anchor in ${rel(file)}: ${value}`);
      continue;
    }
    let path = value;
    if (value === `${SITE_URL}/404/`) continue; // Starlight's canonical link on the 404 page
    if (value.startsWith(SITE_URL)) path = value.slice(SITE_URL.length) || '/';
    if (!path.startsWith('/') || path.startsWith('//')) continue;
    const [pathname, fragment] = decodeURIComponent(path.split('?')[0]).split('#');
    const target = resolve(dist, `.${pathname}`);
    try {
      const s = await stat(target);
      const doc = s.isDirectory() ? resolve(target, 'index.html') : target;
      if (s.isDirectory()) await stat(doc);
      if (fragment && ids.has(doc) && !ids.get(doc).has(fragment)) {
        fail(`Missing anchor in ${rel(file)}: ${value}`);
      }
    } catch {
      fail(`Broken link in ${rel(file)}: ${value}`);
    }
  }
}

// ---- unreplaced tokens in anything we publish
const tokenPattern = new RegExp(Object.keys(VERSION_TOKENS).map((t) => t.replaceAll('%', '%')).join('|'));
for (const f of all.filter((f) => /\.(html|md|txt|json|xml)$/.test(f))) {
  const text = await readFile(f, 'utf8');
  const m = text.match(tokenPattern);
  if (m) fail(`Unreplaced token ${m[0]} in ${rel(f)}`);
}

// ---- every docs page has a Markdown twin; llms.txt links resolve
const manifest = JSON.parse(await readFile(resolve(dist, 'ai/manifest.json'), 'utf8'));
for (const page of manifest.pages) {
  const htmlPath = resolve(dist, `.${new URL(page.url).pathname}`, 'index.html');
  if (!existsSync(htmlPath)) fail(`Manifest page without HTML: ${page.url}`);
}
// Every docs route (everything except the landing page and 404) needs its Markdown twin.
for (const f of htmlFiles) {
  if (!f.endsWith('/index.html')) continue;
  const route = rel(f).replace(/\/index\.html$/, '').replace(/^\//, '');
  if (!route) continue;
  if (!existsSync(resolve(dist, 'ai/pages', `${route}.md`))) fail(`No Markdown twin for /${route}/`);
}
const llms = await readFile(resolve(dist, 'llms.txt'), 'utf8');
for (const m of llms.matchAll(/\]\((https?:\/\/[^)\s]+)\)/g)) {
  if (!m[1].startsWith(SITE_URL)) continue;
  const pathname = new URL(m[1]).pathname;
  const target = resolve(dist, `.${pathname}`);
  const ok = existsSync(target) && ((await stat(target)).isFile() || existsSync(resolve(target, 'index.html')));
  if (!ok) fail(`llms.txt links to a missing file: ${m[1]}`);
}

// ---- manifest checksums
for (const item of [...manifest.pages.map((p) => ({ url: p.markdown, sha256: p.sha256 })), ...manifest.artifacts]) {
  const bytes = await readFile(resolve(dist, `.${new URL(item.url).pathname}`));
  if (createHash('sha256').update(bytes).digest('hex') !== item.sha256) fail(`Checksum mismatch: ${item.url}`);
}
if (manifest.pages.length < 40) fail(`Unexpectedly small documentation export (${manifest.pages.length} pages)`);

// ---- GitHub links into this repository (and zeroj-usecases, when a checkout is available)
const repos = [{ prefix: 'https://github.com/bloxbean/zeroj/', root: REPO_ROOT }];
if (process.env.ZEROJ_USECASES_DIR) {
  repos.push({ prefix: 'https://github.com/bloxbean/zeroj-usecases/', root: resolve(process.env.ZEROJ_USECASES_DIR) });
}
const seen = new Set();
for (const [file, page] of html) {
  for (const m of page.matchAll(/href="(https:\/\/github\.com\/bloxbean\/[^"#?]+)/g)) {
    for (const { prefix, root } of repos) {
      if (!m[1].startsWith(prefix)) continue;
      const tail = m[1].slice(prefix.length).match(/^(?:blob|tree|edit)\/main\/(.+)$/);
      if (!tail) continue;
      const path = decodeURIComponent(tail[1]).replace(/\/$/, '');
      if (m[1].includes('/edit/main/www/')) continue; // Starlight "Edit page" links
      const key = `${root}|${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!existsSync(resolve(root, path))) fail(`GitHub link to a missing path in ${rel(file)}: ${m[1]}`);
    }
  }
}

if (failures.length) {
  console.error([...new Set(failures)].join('\n'));
  console.error(`\ncheck-site: ${new Set(failures).size} problem(s)`);
  process.exit(1);
}
console.log(
  `check-site: ${htmlFiles.length} HTML pages, ${manifest.pages.length} Markdown twins and ${manifest.artifacts.length} AI artifacts verified.`,
);
