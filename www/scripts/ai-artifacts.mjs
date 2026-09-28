// Generates the machine-readable side of the site (the "AI-ready" artifacts):
//
//   /llms.txt                curated index, llmstxt.org convention
//   /llms-full.txt           every docs page concatenated as one Markdown file
//   /ai/pages/<slug>.md      a raw Markdown twin of every docs page ("View Markdown")
//   /ai/starter-pack.md      the AI Starter Pack as a drop-in CLAUDE.md / AGENTS.md / Cursor rule
//   /ai/index.md             raw copy of the "Build with AI" page
//   /ai/catalog.json         symbolic circuit API catalog extracted from the Java sources
//   /ai/manifest.json        versions, source revision, and SHA-256 of every exported file
//
// Everything is derived from src/content/docs and the ZeroJ Java sources at build time; nothing is
// committed. `astro build` writes into dist/ (see ai-integration.mjs), `astro dev` serves the same
// files from memory, and `npm run generate` writes them to .ai-preview/ for inspection.

import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  CCL_VERSION,
  CONTENT_ROOT,
  JULC_VERSION,
  REPO_ROOT,
  REPO_URL,
  SITE_URL,
  USECASES_URL,
  ZEROJ_DEV_VERSION,
  ZEROJ_RELEASED,
  ZEROJ_VERSION,
  replaceVersionTokens,
  sourceRevision,
} from '../site.config.mjs';
import { buildCatalog, renderCatalogMarkdown } from './circuit-catalog.mjs';

// Sidebar order (mirrors astro.config.mjs). Pages are sorted by section, then `sidebar.order`.
export const SECTIONS = [
  { dir: 'start', title: 'Start here' },
  { dir: 'learn', title: 'Learn zero-knowledge (concepts)' },
  { dir: 'tutorials', title: 'Tutorials' },
  { dir: 'guides/circuits', title: 'Guides: circuits' },
  { dir: 'guides/proving', title: 'Guides: proving' },
  { dir: 'guides/verifying', title: 'Guides: verifying' },
  { dir: 'guides/credentials', title: 'Guides: credentials & state' },
  { dir: 'use-cases', title: 'Use cases' },
  { dir: 'reference', title: 'Reference' },
  { dir: 'ai', title: 'Build with AI' },
];

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

async function listDocs(dir, prefix = '') {
  const out = [];
  let entries = [];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await listDocs(resolve(dir, entry.name), rel)));
    else if (/\.mdx?$/.test(entry.name)) out.push(rel);
  }
  return out;
}

function splitFrontmatter(raw, file) {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!m) throw new Error(`[ai] missing frontmatter: ${file}`);
  const data = parseYaml(m[1]) ?? {};
  if (!data.title || !data.description) {
    throw new Error(`[ai] ${file}: frontmatter needs both title and description`);
  }
  return { data, body: m[2] };
}

export function slugOf(rel) {
  const noExt = rel.replace(/\.mdx?$/, '');
  return noExt === 'index' ? '' : noExt.replace(/\/index$/, '');
}

export const pageUrl = (slug) => (slug ? `${SITE_URL}/${slug}/` : `${SITE_URL}/`);
export const markdownUrl = (slug) => `${SITE_URL}/ai/pages/${slug || 'index'}.md`;

function sectionIndex(slug) {
  // Longest matching directory wins (guides/circuits before guides).
  let best = -1;
  let bestLen = -1;
  SECTIONS.forEach((s, i) => {
    if ((slug === s.dir || slug.startsWith(`${s.dir}/`)) && s.dir.length > bestLen) {
      best = i;
      bestLen = s.dir.length;
    }
  });
  return best === -1 ? SECTIONS.length : best;
}

export async function loadPages() {
  const pages = [];
  for (const rel of await listDocs(CONTENT_ROOT)) {
    const raw = await readFile(resolve(CONTENT_ROOT, rel), 'utf8');
    const { data, body } = splitFrontmatter(raw, rel);
    const slug = slugOf(rel);
    pages.push({
      rel,
      slug,
      title: String(data.title),
      description: String(data.description),
      order: Number(data.sidebar?.order ?? 999),
      section: sectionIndex(slug),
      mdx: rel.endsWith('.mdx'),
      body,
    });
  }
  pages.sort((a, b) => a.section - b.section || a.order - b.order || a.title.localeCompare(b.title));
  return pages;
}

// ---------------------------------------------------------------------------------------------
// Markdown export: MDX components → plain Markdown, internal links → absolute URLs.

function attr(attrs, name) {
  return attrs.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`))?.[1] ?? attrs.match(new RegExp(`${name}\\s*=\\s*'([^']*)'`))?.[1];
}

function absolutize(href) {
  if (!href) return href;
  if (href.startsWith('/') && !href.startsWith('//')) return `${SITE_URL}${href}`;
  return href;
}

const ASIDE_LABEL = { note: 'Note', tip: 'Tip', caution: 'Caution', danger: 'Danger' };

// Starlight `:::kind[Title]` asides → Markdown blockquotes (outside fenced code).
function convertDirectives(text) {
  const lines = text.split('\n');
  const out = [];
  let fence = null;
  let inAside = false;
  for (const line of lines) {
    const f = line.match(/^\s*(```+|~~~+)/);
    if (f) {
      if (!fence) fence = f[1];
      else if (line.trim().startsWith(fence)) fence = null;
    }
    if (!fence && !f) {
      const open = line.match(/^:::(note|tip|caution|danger)(?:\[(.*)\])?\s*$/);
      if (open && !inAside) {
        inAside = true;
        const label = ASIDE_LABEL[open[1]];
        out.push(`> **${open[2] ? `${label}: ${open[2]}` : label}**`, '>');
        continue;
      }
      if (inAside && /^:::\s*$/.test(line)) {
        inAside = false;
        continue;
      }
    }
    out.push(inAside ? (line.length ? `> ${line}` : '>') : line);
  }
  return out.join('\n');
}

export function toPlainMarkdown(body, { mdx }) {
  let text = replaceVersionTokens(body);
  if (mdx) {
    text = text
      .replace(/^\s*import\s[^;\n]+from\s+['"][^'"]+['"];?\s*$/gm, '')
      .replace(/<LinkCard\s([^>]*?)\/>/g, (_, a) => {
        const desc = attr(a, 'description');
        return `- [${attr(a, 'title')}](${absolutize(attr(a, 'href'))})${desc ? `: ${desc}` : ''}`;
      })
      .replace(/<Card\s([^>]*?)>/g, (_, a) => `**${attr(a, 'title') ?? ''}**\n`)
      .replace(/<TabItem\s([^>]*?)>/g, (_, a) => `**${attr(a, 'label') ?? ''}**\n`)
      .replace(/<Aside\s*([^>]*?)>/g, (_, a) => {
        const kind = ASIDE_LABEL[attr(a, 'type') ?? 'note'] ?? 'Note';
        const title = attr(a, 'title');
        return `**${title ? `${kind}: ${title}` : kind}:** `;
      })
      .replace(/<Badge\s([^>]*?)\/>/g, (_, a) => `[${attr(a, 'text') ?? ''}]`)
      // Interactive illustrations (src/components/walkthrough/, named *Walkthrough, *Explainer or
      // *Diagram) have no text form of their own: the page text covers the same ground, and any
      // diagram they replace is kept for these exports inside <TextOnly>.
      .replace(
        /<[A-Z]\w*(?:Walkthrough|Explainer|Diagram)\b[^>]*\/>/g,
        '_The web version of this page has an interactive illustration here._',
      )
      .replace(/<\/?TextOnly>/g, '')
      .replace(/<ReleaseNotice\s*\/>/g, () =>
        ZEROJ_RELEASED
          ? ''
          : `> **Caution:** ZeroJ ${ZEROJ_VERSION} isn't on Maven Central yet, so these snippets won't resolve until it's published. Build from source with \`./gradlew publishToMavenLocal\` meanwhile (local versions are \`${ZEROJ_VERSION}-<commit>-SNAPSHOT\`).`,
      )
      .replace(/<\/?(Steps|Tabs|CardGrid|FileTree|Card|TabItem|Aside)(\s[^>]*)?>/g, '');
  }
  text = convertDirectives(text);
  // Root-relative Markdown links and bare href attributes → absolute site URLs.
  text = text.replace(/\]\((\/(?!\/)[^)\s]*)\)/g, (_, href) => `](${SITE_URL}${href})`);
  return text.replace(/\n{3,}/g, '\n\n').trim();
}

function demoteHeadings(markdown, by) {
  let fence = null;
  return markdown
    .split('\n')
    .map((line) => {
      const f = line.match(/^\s*(```+|~~~+)/);
      if (f) {
        if (!fence) fence = f[1];
        else if (line.trim().startsWith(fence)) fence = null;
        return line;
      }
      if (fence) return line;
      return line.replace(/^(#{1,4})\s/, (_, h) => `${'#'.repeat(h.length + by)} `);
    })
    .join('\n');
}

function injectBetween(body, name, replacement) {
  const start = `<!-- catalog:${name}-start -->`;
  const end = `<!-- catalog:${name}-end -->`;
  const i = body.indexOf(start);
  const j = body.indexOf(end, i + start.length);
  if (i === -1 || j === -1) return body;
  return `${body.slice(0, i + start.length)}\n\n${replacement.trim()}\n\n${body.slice(j)}`;
}

// ---------------------------------------------------------------------------------------------

const KEY_FACTS = [
  'ZeroJ is a Java-first zero-knowledge proof toolkit for Cardano: define circuits in Java, prove with a pure-Java prover, verify in Java (off-chain) or on Cardano (Plutus V3 via JuLC).',
  'Status: experimental research software, not externally audited, not for production or value-bearing/mainnet use. "Beta" components are feature-complete and correctness-tested but not audited.',
  '**Groth16 on BLS12-381 is the supported path for the current release.** PlonK (prover, verifier and on-chain validators) is experimental: make no correctness claims about it and do not choose it by default. BN254 is legacy and disabled by default.',
  `Maven group and Java packages are \`org.zeroj\` (from 0.1.0-pre12). Current version: ${ZEROJ_VERSION}${ZEROJ_RELEASED ? '' : ' (not on Maven Central yet; build from source meanwhile)'}. Import the BOM \`org.zeroj:zeroj-bom-core:${ZEROJ_VERSION}\`; opt-in modules (zeroj-verifier-plonk, zeroj-bbs, zeroj-mpf-poseidon, zeroj-jmt-poseidon) need explicit versions. Releases up to 0.1.0-pre11 used \`com.bloxbean.cardano\`.`,
  'Java 25+. Nothing beyond a JDK is required for the default path (no Rust, Node.js, native toolchain or external CLIs); blst acceleration and snarkjs/circom interop are optional. `zeroj-verifier-groth16` carries the blst-java JNI jar for its native verifier, and `VerifierRegistry.withServiceLoader()` lists that verifier first: construct `Groth16BLS12381PureJavaVerifier` explicitly for a pure-Java path.',
  'Write application circuits with annotations: `@ZKCircuit`, `@Prove`, `@Public`/`@Secret`, symbolic types `ZkField`, `ZkBool`, `ZkUInt` (always with `@UInt(bits = N)`), `ZkArray`/`ZkBits`/`ZkBytes` (with `@FixedSize`). The annotation processor generates a `<Name>Circuit` companion. Never use Java `if`, `&&`, `||` on secret values — use `ZkBool.and/or/not/select`.',
  'For Cardano circuits hash with Poseidon using explicit BLS12-381 parameters (`PoseidonParamsBLS12_381T3.INSTANCE`). MiMC and the no-params Poseidon overload are BN254-oriented; do not use them for Cardano.',
  'Single-party trusted setup (`PowersOfTauBLS381.generate`, `Groth16Keys.setupInMemory`) is for development and tests only and requires `-Dzeroj.allowInsecureTrustedSetup=true`. Production keys come from a multi-party ceremony (snarkjs `.zkey`, imported into ZeroJ).',
  'Every proof is freshly blinded; there is no public deterministic/unblinded prove API.',
  'A valid proof is not authorization. On-chain, the reusable `Groth16BLS12381Verifier` only checks the math; real validators compose `Groth16BLS12381Lib`, bind the proof to the spend and recipient using values computed from ScriptContext, prevent replay with nullifiers or state, and enforce business policy. Do not lock funds with `Groth16BLS12381TxOutRefBindingVerifier`: it reads its spend binding from the guarded UTxO\'s own datum, which no real UTxO can satisfy.',
  'An honest witness passing does not make a circuit sound: test invalid witnesses for every constraint.',
];

export function starterPackStamp() {
  return `<!-- ZeroJ AI Starter Pack · zerojVersion: ${ZEROJ_VERSION} · julcVersion: ${JULC_VERSION} · cclVersion: ${CCL_VERSION} · source: ${SITE_URL}/ai/starter-pack.md -->`;
}

/**
 * Build every AI artifact in memory. Returns a map of site-relative path → file content.
 */
export async function buildAiArtifacts() {
  const pages = await loadPages();
  const catalog = await buildCatalog();
  const catalogMd = renderCatalogMarkdown(catalog);
  const revision = sourceRevision();
  const files = new Map();

  const exports = [];
  for (const page of pages) {
    let body = page.body;
    if (page.slug === 'ai/starter-pack') body = injectBetween(body, 'circuit-api', catalogMd);
    const markdown = toPlainMarkdown(body, { mdx: page.mdx });
    const exported = `# ${page.title}\n\n> ${page.description}\n\nCanonical URL: ${pageUrl(page.slug)}\n\n${markdown}\n`;
    files.set(`ai/pages/${page.slug || 'index'}.md`, exported);
    exports.push({ ...page, markdown });

    if (page.slug === 'ai/starter-pack') {
      files.set('ai/starter-pack.md', `${starterPackStamp()}\n\n# ${page.title}\n\n${markdown}\n`);
    }
    if (page.slug === 'ai') files.set('ai/index.md', `# ${page.title}\n\n${markdown}\n`);
  }

  // ---------- llms.txt ----------
  const idx = [];
  idx.push('# ZeroJ', '');
  idx.push(
    '> ZeroJ is a Java-first zero-knowledge proof toolkit for Cardano. Define circuits in Java, prove them with a pure-Java Groth16 prover on BLS12-381, verify proofs in any JVM, and verify them on-chain in Cardano Plutus V3 validators built with JuLC. Also includes BBS selective-disclosure credentials and snarkjs/circom interoperability.',
    '',
  );
  idx.push(`zerojVersion: ${ZEROJ_VERSION}`, `julcVersion: ${JULC_VERSION}`, `cclVersion: ${CCL_VERSION}`, '');
  idx.push('Key facts an AI agent must know before generating ZeroJ code:', '');
  for (const fact of KEY_FACTS) idx.push(`- ${fact}`);
  idx.push('', '## Start here for AI agents', '');
  idx.push(
    `- [AI Starter Pack](${SITE_URL}/ai/starter-pack.md): the single best file to ingest — rules, idioms, anti-patterns, a symbolic circuit API catalog and canonical code. Drop it into CLAUDE.md, AGENTS.md or a Cursor rule.`,
    `- [llms-full.txt](${SITE_URL}/llms-full.txt): every documentation page in one Markdown file.`,
    `- [Circuit API catalog (JSON)](${SITE_URL}/ai/catalog.json): symbolic circuit types, annotations and gadget adapters extracted from the Java sources.`,
    `- [Manifest](${SITE_URL}/ai/manifest.json): versions, source revision and checksums of every exported file.`,
    `- [Build with AI](${SITE_URL}/ai/): setup for Claude Code, Cursor, Codex, Continue and chat assistants.`,
    '',
  );
  let current = -2;
  for (const page of exports) {
    if (page.slug.startsWith('ai')) continue; // listed above
    if (page.section !== current) {
      current = page.section;
      idx.push(`## ${SECTIONS[page.section]?.title ?? 'Other'}`, '');
    }
    idx.push(`- [${page.title}](${markdownUrl(page.slug)}): ${page.description}`);
    const next = exports[exports.indexOf(page) + 1];
    if (!next || next.section !== page.section) idx.push('');
  }
  idx.push('## Source code and examples', '');
  idx.push(`- ZeroJ repository: ${REPO_URL}`);
  idx.push(`- Runnable end-to-end demo apps: ${USECASES_URL}`);
  idx.push(`- Every page is also available as HTML at the canonical URL shown inside its Markdown twin.`, '');
  files.set('llms.txt', idx.join('\n'));

  // ---------- llms-full.txt ----------
  const full = [];
  full.push('# ZeroJ — full documentation (for AI ingestion)', '');
  full.push('> Every page of the ZeroJ documentation site concatenated into one Markdown file.', '');
  full.push(`zerojVersion: ${ZEROJ_VERSION}`, `Site: ${SITE_URL}`, `Repository: ${REPO_URL}`, `Source revision: ${revision}`, '');
  full.push('## Key facts', '');
  for (const fact of KEY_FACTS) full.push(`- ${fact}`);
  full.push('', '## Table of contents', '');
  for (const page of exports) full.push(`- [${SECTIONS[page.section]?.title ?? 'Other'} → ${page.title}](${pageUrl(page.slug)})`);
  full.push('');
  for (const page of exports) {
    full.push('---', '', `## ${page.title}`, '', `Source: ${pageUrl(page.slug)}`, '', `> ${page.description}`, '');
    full.push(demoteHeadings(page.markdown, 1), '');
  }
  files.set('llms-full.txt', full.join('\n'));

  // ---------- catalog.json ----------
  files.set('ai/catalog.json', JSON.stringify(catalog, null, 2) + '\n');

  // ---------- manifest.json ----------
  const manifestPages = exports.map((p) => ({
    title: p.title,
    description: p.description,
    url: pageUrl(p.slug),
    markdown: markdownUrl(p.slug),
    sha256: sha256(files.get(`ai/pages/${p.slug || 'index'}.md`)),
  }));
  const artifacts = ['llms.txt', 'llms-full.txt', 'ai/starter-pack.md', 'ai/index.md', 'ai/catalog.json']
    .filter((name) => files.has(name))
    .map((name) => ({ url: `${SITE_URL}/${name}`, sha256: sha256(files.get(name)) }));
  files.set(
    'ai/manifest.json',
    JSON.stringify(
      {
        schemaVersion: 1,
        site: SITE_URL,
        zerojVersion: ZEROJ_VERSION,
        zerojReleased: ZEROJ_RELEASED,
        zerojDevelopmentVersion: ZEROJ_DEV_VERSION,
        julcVersion: JULC_VERSION,
        cclVersion: CCL_VERSION,
        sourceRepository: REPO_URL,
        sourceRevision: revision,
        note: 'Source revision at build time. Hashes describe the generated content, including local edits. The documentation tracks the main branch and may describe features newer than the latest published release.',
        pages: manifestPages,
        artifacts,
      },
      null,
      2,
    ) + '\n',
  );

  return files;
}

export async function writeAiArtifacts(outDir, logger = console) {
  const files = await buildAiArtifacts();
  for (const [rel, content] of files) {
    const target = resolve(outDir, rel);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, 'utf8');
  }
  const pageCount = [...files.keys()].filter((k) => k.startsWith('ai/pages/')).length;
  logger.info(`[ai] wrote llms.txt, llms-full.txt, ${pageCount} Markdown pages, catalog and manifest to ${relative(REPO_ROOT, outDir) || outDir}`);
  return files;
}
