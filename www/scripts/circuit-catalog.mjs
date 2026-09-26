// Extracts a machine-readable catalog of the symbolic circuit API (annotations, Zk* types and the
// Zk* gadget adapters) straight from the Java sources, so AI agents get real signatures instead
// of guessing. Published as /ai/catalog.json and rendered into the AI Starter Pack.
//
// This is a pragmatic source scan, not a Java parser: it reads public members of the listed files.
// If a listed file disappears or yields no members the build fails, so the catalog cannot silently
// go stale.

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { REPO_ROOT, ZEROJ_VERSION } from '../site.config.mjs';

const ANNOTATION_PKG = 'zeroj-circuit-annotation-api/src/main/java/org/zeroj/circuit/annotation';
const GADGET_PKG = 'zeroj-circuit-lib/src/main/java/org/zeroj/circuit/lib/zk';

const GROUPS = [
  {
    key: 'annotations',
    title: 'Annotations',
    module: 'org.zeroj:zeroj-circuit-annotation-api',
    package: 'org.zeroj.circuit.annotation',
    kind: 'annotation',
    files: ['ZKCircuit', 'Prove', 'Public', 'Secret', 'UInt', 'FixedSize', 'CircuitParam', 'FieldElement', 'Order'].map(
      (n) => `${ANNOTATION_PKG}/${n}.java`,
    ),
  },
  {
    key: 'types',
    title: 'Symbolic types',
    module: 'org.zeroj:zeroj-circuit-annotation-api',
    package: 'org.zeroj.circuit.annotation',
    kind: 'class',
    files: ['ZkContext', 'ZkField', 'ZkBool', 'ZkUInt', 'ZkArray', 'ZkBits', 'ZkBytes'].map((n) => `${ANNOTATION_PKG}/${n}.java`),
  },
  {
    key: 'gadgets',
    title: 'Gadget adapters',
    module: 'org.zeroj:zeroj-circuit-lib',
    package: 'org.zeroj.circuit.lib.zk',
    kind: 'class',
    files: [
      'ZkPoseidon',
      'ZkPoseidonN',
      'ZkMerkle',
      'ZkSha512',
      'ZkHmacSha512',
      'ZkBlake2b',
      'ZkCip1852',
      'ZkPedersen',
      'ZkJubjubPoint',
      'ZkEdDSAJubjub',
      'ZkMiMC',
    ].map((n) => `${GADGET_PKG}/${n}.java`),
  },
];

const NOTES = {
  ZkMiMC: 'BN254-only. Do not use for Cardano (BLS12-381) circuits.',
  ZkPoseidon: 'For Cardano pass PoseidonParamsBLS12_381T3.INSTANCE explicitly.',
  ZkPoseidonN: 'For Cardano pass PoseidonParamsBLS12_381T3.INSTANCE explicitly.',
  ZkMerkle: 'For Cardano use the *Poseidon methods with PoseidonParamsBLS12_381T3.INSTANCE; HashType.MIMC and no-params POSEIDON are BN254/off-chain paths.',
  ZkUInt: 'Declare inputs with @UInt(bits = N); construction adds range constraints.',
};

// Line comments only; `://` (URLs inside Javadoc) is left alone. Block comments are skipped by
// the scanner in publicMembers, which also records Javadoc.
function stripComments(src) {
  return src.replace(/(^|[^:"])\/\/[^\n]*/g, '$1');
}

function firstSentence(javadoc) {
  const text = javadoc
    .replace(/^\/\*\*|\*\/$/g, '')
    .split('\n')
    .map((l) => l.replace(/^\s*\*\s?/, ''))
    .filter((l) => !l.trim().startsWith('@'))
    .join(' ')
    .replace(/\{@(?:code|link|linkplain)\s+([^}]*)\}/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const m = text.match(/^(.+?[.!?])(\s|$)/);
  return (m ? m[1] : text).slice(0, 240);
}

function typeDoc(src, name) {
  const re = new RegExp(`(\\/\\*\\*[\\s\\S]*?\\*\\/)\\s*(?:@[\\w.]+(?:\\([^)]*\\))?\\s*)*public\\s+(?:final\\s+|abstract\\s+|sealed\\s+)*(?:class|interface|@interface|record|enum)\\s+${name}\\b`);
  const m = src.match(re);
  return m ? firstSentence(m[1]) : '';
}

// Public methods of the top-level type (members of nested types are skipped by brace depth).
function publicMembers(src, kind, name) {
  const members = [];
  const clean = stripComments(src);
  // Locate the type declaration with comments blanked out (same length, so indices line up);
  // Javadoc often mentions `class` next to `{@code ...}`.
  const blanked = clean.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
  const bodyStart = blanked.search(new RegExp(`\\b(class|interface|@interface|record|enum)\\s+${name}\\b[^{]*\\{`));
  if (bodyStart === -1) return members;
  const open = blanked.indexOf('{', bodyStart);
  let depth = 0;
  let i = open;
  let lastDoc = '';
  let buf = '';
  for (; i < clean.length; i++) {
    const ch = clean[i];
    if (clean.startsWith('/*', i)) {
      const end = clean.indexOf('*/', i + 2);
      if (clean.startsWith('/**', i) && depth === 1) lastDoc = clean.slice(i, end + 2);
      i = end + 1;
      continue;
    }
    // Skip string, text-block and char literals so braces inside them don't affect depth.
    if (clean.startsWith('"""', i)) {
      const end = clean.indexOf('"""', i + 3);
      if (depth === 1) buf += '""';
      i = end + 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < clean.length && clean[j] !== ch) j += clean[j] === '\\' ? 2 : 1;
      if (depth === 1) buf += `${ch}${ch}`;
      i = j;
      continue;
    }
    if (ch === '{') {
      if (depth === 1) {
        collect(buf);
        buf = '';
      }
      depth++;
      continue;
    }
    if (ch === '}') {
      depth--;
      if (depth === 0) break;
      if (depth === 1) {
        buf = '';
        lastDoc = '';
      }
      continue;
    }
    if (depth === 1) {
      if (ch === ';') {
        collect(buf);
        buf = '';
      } else buf += ch;
    }
  }

  function collect(decl) {
    const text = decl.replace(/\s+/g, ' ').trim();
    const doc = lastDoc ? firstSentence(lastDoc) : '';
    lastDoc = '';
    if (!text) return;
    if (kind === 'annotation') {
      // Annotation element: `int bits() default 0`
      const m = text.match(/^(?:public\s+)?([\w.<>\[\]?, ]+?)\s+(\w+)\s*\(\s*\)(?:\s+default\s+(.+))?$/);
      if (m) members.push({ name: m[2], signature: `${m[1]} ${m[2]}()${m[3] ? ` default ${m[3]}` : ''}`, doc });
      return;
    }
    if (!/^(?:@\w+(?:\([^)]*\))?\s+)*public\s/.test(text)) return;
    if (/\b(class|interface|record|enum)\s/.test(text)) return;
    const m = text.match(
      /^(?:@\w+(?:\([^)]*\))?\s+)*public\s+((?:static\s+|final\s+|default\s+|abstract\s+|synchronized\s+)*)(<[^>]+>\s+)?([\w.<>\[\]?, ]+?)\s+(\w+)\s*\((.*)\)(?:\s*throws\s+[\w., ]+)?$/,
    );
    if (!m) return; // fields and constructors are skipped
    const isStatic = /\bstatic\b/.test(m[1]);
    const generics = m[2] ? m[2].trim() + ' ' : '';
    const params = m[5].replace(/\s*,\s*/g, ', ').replace(/final\s+/g, '').trim();
    members.push({
      name: m[4],
      static: isStatic,
      signature: `${isStatic ? 'static ' : ''}${generics}${m[3].trim()} ${m[4]}(${params})`,
      doc,
    });
  }
  return members;
}

export async function buildCatalog() {
  const groups = [];
  for (const group of GROUPS) {
    const types = [];
    for (const file of group.files) {
      const name = file.split('/').pop().replace(/\.java$/, '');
      let src;
      try {
        src = await readFile(resolve(REPO_ROOT, file), 'utf8');
      } catch {
        throw new Error(`[catalog] missing source file ${file} — update scripts/circuit-catalog.mjs`);
      }
      const members = publicMembers(src, group.kind, name);
      if (group.kind !== 'annotation' && members.length === 0) {
        throw new Error(`[catalog] no public methods found in ${file}`);
      }
      types.push({
        name,
        qualifiedName: `${group.package}.${name}`,
        doc: typeDoc(src, name),
        note: NOTES[name],
        source: file,
        members,
      });
    }
    groups.push({ key: group.key, title: group.title, module: group.module, package: group.package, types });
  }
  return {
    schemaVersion: 1,
    zerojVersion: ZEROJ_VERSION,
    note: 'Extracted from the ZeroJ Java sources at documentation build time. Public members only; the annotation processor also generates a <Name>Circuit companion per @ZKCircuit class.',
    groups,
  };
}

export function renderCatalogMarkdown(catalog) {
  const out = [];
  out.push('*Generated from the Java sources at build time — the same data as [/ai/catalog.json](/ai/catalog.json).*', '');
  for (const group of catalog.groups) {
    out.push(`### ${group.title} (\`${group.package}\`, module \`${group.module}\`)`, '');
    for (const type of group.types) {
      out.push(`#### ${type.name}`, '');
      if (type.doc) out.push(`*${type.doc}*`, '');
      if (type.note) out.push(`> ${type.note}`, '');
      if (type.members.length === 0) {
        out.push('_(marker annotation — no elements)_', '');
        continue;
      }
      for (const m of type.members) out.push(`- \`${m.signature}\`${m.doc ? ` — ${m.doc}` : ''}`);
      out.push('');
    }
  }
  return out.join('\n');
}
