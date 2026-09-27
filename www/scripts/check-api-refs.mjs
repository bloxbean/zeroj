// Guards the docs against invented APIs. Scans every ```java block in src/content/docs and checks,
// against the ZeroJ main sources in this checkout:
//   - `import org.zeroj.…` statements resolve to a real type or package
//   - every referenced class is a ZeroJ type, a type declared in the docs themselves (including the
//     generated `<Name>Circuit` companion of a documented @ZKCircuit class), or a known external type
//   - `ZeroJType.method(` and `ZeroJType.CONSTANT` refer to a member declared in that type's source
//
// It is a source-text check, not a compiler: it cannot type-check instance calls. It exists to catch
// the most common documentation failure — a class or static method that doesn't exist.
//
// Usage: node scripts/check-api-refs.mjs [--verbose]

import { readFile, readdir } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { CONTENT_ROOT, REPO_ROOT } from '../site.config.mjs';

const verbose = process.argv.includes('--verbose');

// Types from the JDK, Cardano Client Lib, JuLC, JUnit and friends that snippets may use.
const EXTERNAL = new Set(
  `
  Object String StringBuilder System Math Integer Long Short Byte Boolean Character Double Float Number Void
  BigInteger BigDecimal List ArrayList LinkedList Map HashMap LinkedHashMap TreeMap Set HashSet LinkedHashSet
  Arrays Collections Objects Optional Iterator Iterable Collection Stream IntStream LongStream Collectors
  Function Supplier Consumer Predicate BiFunction Runnable Callable Comparator Record Enum Class Thread
  Files Path Paths File InputStream OutputStream Reader Writer IOException UncheckedIOException
  StandardCharsets Charset HexFormat Base64 UUID Duration Instant LocalDate Clock SecureRandom Random
  MessageDigest Exception RuntimeException IllegalArgumentException IllegalStateException ArithmeticException
  NullPointerException UnsupportedOperationException ArrayIndexOutOfBoundsException OutOfMemoryError Error
  AutoCloseable Override Deprecated SuppressWarnings FunctionalInterface SafeVarargs Arena MemorySegment
  Test BeforeAll BeforeEach AfterAll AfterEach TempDir ParameterizedTest ValueSource MethodSource CsvSource
  Assertions Assumptions DisplayName Nested Disabled Tag Timeout RepeatedTest Property ForAll
  QuickTxBuilder Tx ScriptTx Amount AddressProvider Address Networks Network Account BackendService
  BFBackendService PlutusData ConstrPlutusData ListPlutusData BigIntPlutusData BytesPlutusData MapPlutusData
  PlutusScript PlutusV3Script SignerProviders Utxo UtxoSupplier DefaultUtxoSupplier Result TxResult
  Blake2bUtil HexUtil Credential ScriptContext TxInfo TxOut TxOutRef TxId Value Interval
  JulcScriptLoader Builtins SpendingValidator MintingValidator WithdrawValidator CertifyingValidator
  VotingValidator ProposingValidator Entrypoint Param OnchainLibrary JulcList JulcMap NewType
  Tuple2 Tuple3 ContextsLib ListsLib ValuesLib MapLib OutputLib CryptoLib ByteStringLib AddressLib BlsLib
  SpringBootApplication RestController Service Component Bean Autowired
  `.split(/\s+/).filter(Boolean),
);

async function walk(dir, filter) {
  const out = [];
  let entries = [];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = resolve(dir, e.name);
    if (e.isDirectory()) {
      if (['build', 'node_modules', '.git', '.gradle', 'test', 'www', '.claude'].includes(e.name)) continue;
      out.push(...(await walk(p, filter)));
    } else if (filter(p)) out.push(p);
  }
  return out;
}

// ---- index ZeroJ main sources: simple name -> [{ file, text }], packages
const sources = (await walk(REPO_ROOT, (p) => p.endsWith('.java') && p.includes('/src/main/java/'))).filter((p) =>
  /\/src\/main\/java\/org\/zeroj\//.test(p),
);
const byName = new Map();
const packages = new Set();
for (const file of sources) {
  const text = await readFile(file, 'utf8');
  const pkg = file.split('/src/main/java/')[1].split('/').slice(0, -1).join('.');
  packages.add(pkg);
  const add = (name) => {
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push({ file, text, pkg });
  };
  // Top-level and nested type declarations.
  for (const m of text.matchAll(/\b(?:class|interface|record|enum|@interface)\s+([A-Z]\w*)/g)) add(m[1]);
}

function declares(entries, member) {
  const re = new RegExp(
    `(?:\\b${member}\\s*\\(|\\b${member}\\s*[,;=)]|\\b(?:class|interface|record|enum)\\s+${member}\\b|^\\s*${member}\\s*[,;(]|\\brecord\\s+\\w+\\s*\\([^)]*\\b${member}\\b)`,
    'm',
  );
  return entries.some(({ text }) => re.test(text));
}

// ---- collect java blocks
const docs = await walk(CONTENT_ROOT, (p) => /\.mdx?$/.test(p));
const blocks = [];
for (const file of docs) {
  const text = await readFile(file, 'utf8');
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const open = lines[i].match(/^(\s*)(```+|~~~+)\s*java\b/);
    if (!open) continue;
    const fence = open[2];
    const start = i + 1;
    let j = start;
    while (j < lines.length && !lines[j].trim().startsWith(fence)) j++;
    blocks.push({ file, line: start + 1, code: lines.slice(start, j).join('\n') });
    i = j;
  }
}

// Types declared anywhere in the docs (records, helper classes) and @ZKCircuit companions.
const docTypes = new Set();
for (const { code } of blocks) {
  for (const m of code.matchAll(/\b(?:class|interface|record|enum)\s+([A-Z]\w*)/g)) {
    docTypes.add(m[1]);
    docTypes.add(`${m[1]}Circuit`); // generated companion
  }
}

const problems = [];
const warn = [];
const where = (b, offset) => `${relative(CONTENT_ROOT, b.file)}:${b.line + offset}`;

for (const b of blocks) {
  const code = b.code.replace(/\/\/[^\n]*/g, (c) => ' '.repeat(c.length)).replace(/"(?:[^"\\\n]|\\.)*"/g, (s) => `"${' '.repeat(s.length - 2)}"`);
  const lineOf = (idx) => code.slice(0, idx).split('\n').length - 1;
  const imported = new Map();

  for (const m of code.matchAll(/^\s*import\s+(static\s+)?([\w.]+)(\.\*)?\s*;/gm)) {
    const [, isStatic, name, star] = m;
    const simple = name.split('.').pop();
    if (!name.startsWith('org.zeroj.')) {
      if (!isStatic) imported.set(simple, name);
      continue;
    }
    if (star && !isStatic) {
      if (!packages.has(name)) problems.push(`${where(b, lineOf(m.index))}: unknown package in import ${name}.*`);
      continue;
    }
    const parts = name.split('.');
    // Find the longest prefix that is a package, then check the remaining type path.
    let k = parts.length - 1;
    while (k > 0 && !packages.has(parts.slice(0, k).join('.'))) k--;
    const pkg = parts.slice(0, k).join('.');
    const typePath = parts.slice(k);
    const top = typePath[0];
    const entries = (byName.get(top) ?? []).filter((e) => e.pkg === pkg);
    if (!pkg || entries.length === 0) {
      problems.push(`${where(b, lineOf(m.index))}: import ${name} does not resolve to a ZeroJ type`);
      continue;
    }
    const rest = isStatic && !star ? typePath.slice(1) : typePath.slice(1);
    for (const member of rest) {
      if (!declares(entries, member)) problems.push(`${where(b, lineOf(m.index))}: ${top} has no member ${member} (import ${name})`);
    }
    if (!isStatic) imported.set(typePath.at(-1), name);
  }

  const known = (name) =>
    byName.has(name) || docTypes.has(name) || EXTERNAL.has(name) || imported.has(name);

  // Static member access: Type.member( / Type.CONSTANT
  for (const m of code.matchAll(/(?<![\w.])([A-Z][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_]\w*)(\s*\()?/g)) {
    const [, type, member, call] = m;
    if (/^[A-Z][A-Z0-9_]*$/.test(type)) continue; // CONSTANT.method(...) — a value, not a type
    if (!call && !/^[A-Z][A-Z0-9_]*$/.test(member)) continue; // Type.Nested etc. handled below
    if (!known(type)) {
      problems.push(`${where(b, lineOf(m.index))}: unknown type ${type} (in ${type}.${member})`);
      continue;
    }
    const entries = byName.get(type);
    if (!entries || docTypes.has(type) || EXTERNAL.has(type)) continue;
    if (member === 'class' || member === 'length') continue;
    if (!declares(entries, member)) {
      // Enum constants/nested types declared in a nested type with the same simple name are covered by
      // `declares`; anything else is a real miss.
      problems.push(`${where(b, lineOf(m.index))}: ${type}.${member} not found in ${entries.map((e) => relative(REPO_ROOT, e.file)).join(', ')}`);
    }
  }

  // Constructors and annotations
  for (const m of code.matchAll(/\bnew\s+([A-Z]\w*)|@([A-Z]\w*)/g)) {
    const type = m[1] ?? m[2];
    if (!known(type)) problems.push(`${where(b, lineOf(m.index))}: unknown type ${type}`);
  }

  // Type positions: `Type name =`, `Type[] name`, generics — flag unknown ZeroJ-looking names only.
  for (const m of code.matchAll(/\b([A-Z][A-Za-z0-9]*)(?:<[^>]*>)?(?:\[\])*\s+[a-z]\w*\s*[=;,)]/g)) {
    const type = m[1];
    if (!known(type) && /^(Zk|Groth16|Plonk|PlonK|Bbs|Snarkjs|Zkey|Ptau|Poseidon|Circuit|Prover|Verif|R1CS|Signal)/.test(type)) {
      problems.push(`${where(b, lineOf(m.index))}: unknown type ${type}`);
    } else if (!known(type) && verbose) {
      warn.push(`${where(b, lineOf(m.index))}: unverified type ${type}`);
    }
  }
}

if (verbose) for (const w of [...new Set(warn)]) console.warn(`warn ${w}`);
if (problems.length) {
  for (const p of [...new Set(problems)]) console.error(p);
  console.error(`\ncheck-api-refs: ${new Set(problems).size} problem(s) in ${blocks.length} Java blocks`);
  process.exit(1);
}
console.log(`check-api-refs: ${blocks.length} Java blocks checked against ${sources.length} ZeroJ source files — no unknown APIs.`);
