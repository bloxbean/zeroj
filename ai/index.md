# Build with AI

ZeroJ is young, so AI models have little or no training data about it. Without context, an assistant will happily invent classes, reach for BN254 or MiMC, skip range checks, or treat a dev-only trusted setup as production-ready. This site ships everything an agent needs to get ZeroJ right on the first try.

## TL;DR

Point your assistant at the **AI Starter Pack** — or at `llms.txt`, and let it pull what it needs.

| Artifact | Use it when |
| --- | --- |
| [`/ai/starter-pack.md`](https://zeroj.dev/ai/starter-pack.md) | **Start here.** One file with the rules, idioms, anti-patterns, error→fix table, canonical code and a generated circuit API catalog. Save it as `CLAUDE.md`, `AGENTS.md` or a Cursor rule. |
| [`/llms.txt`](https://zeroj.dev/llms.txt) | A compact index of the whole site ([llmstxt.org](https://llmstxt.org/) convention) with the key facts an agent must not get wrong. |
| [`/llms-full.txt`](https://zeroj.dev/llms-full.txt) | Every documentation page concatenated into one Markdown file, for tools that ingest a single URL. |
| [`/ai/catalog.json`](https://zeroj.dev/ai/catalog.json) | Machine-readable catalog of the symbolic circuit API — annotations, `Zk*` types and gadget adapters — extracted from the Java sources at build time. |
| [`/ai/manifest.json`](https://zeroj.dev/ai/manifest.json) | ZeroJ, JuLC and Cardano Client Lib versions, the source revision, and a SHA-256 for every exported file. |
| `/ai/pages/<page>.md` | A Markdown twin of every page. Use **View Markdown** or **Copy page for AI** under any page title. |

All of these are regenerated on every build from the same sources as the HTML pages, so they never drift from what you read here.

## Set up your tool

### Claude Code

Save the starter pack as your project's `CLAUDE.md` (Claude Code reads it at the start of every session):

```bash
curl -o CLAUDE.md https://zeroj.dev/ai/starter-pack.md
```

Already have a `CLAUDE.md`? Keep the pack beside it and import it:

```bash
curl -o docs/zeroj-starter-pack.md https://zeroj.dev/ai/starter-pack.md
echo '@docs/zeroj-starter-pack.md' >> CLAUDE.md
```

### Codex, Jules, Aider and other `AGENTS.md` tools

```bash
curl -o AGENTS.md https://zeroj.dev/ai/starter-pack.md
```

### Cursor

```bash
mkdir -p .cursor/rules
curl -o .cursor/rules/zeroj.mdc https://zeroj.dev/ai/starter-pack.md
```

### GitHub Copilot

```bash
mkdir -p .github
curl -o .github/copilot-instructions.md https://zeroj.dev/ai/starter-pack.md
```

### Continue

Add the full docs as a URL context provider in your Continue config:

```json
{
  "contextProviders": [
    { "name": "url", "params": { "url": "https://zeroj.dev/llms-full.txt" } }
  ]
}
```

### ChatGPT, Claude.ai and other chat assistants

Start the conversation with:

```text
I'm building with ZeroJ, a Java zero-knowledge proof toolkit for Cardano.
Before writing any code, read https://zeroj.dev/llms.txt and
https://zeroj.dev/ai/starter-pack.md and follow them strictly:
Groth16 on BLS12-381, annotation-style circuits (@ZKCircuit),
Poseidon with PoseidonParamsBLS12_381T3.INSTANCE, dev-only trusted
setup behind -Dzeroj.allowInsecureTrustedSetup=true, and no APIs that
are not in the docs or the circuit API catalog.
```

If the assistant can't browse, paste the starter pack (or use **Copy page for AI** on the pages you need).

> **Tip: Pin the version**
>
> The starter pack starts with a comment naming the ZeroJ version it was generated for. When you upgrade ZeroJ, refresh the file so your agent learns the new APIs.

## Prompts that work well

Be specific about the statement, what's secret, what's public, and ask for tests that try to cheat:

```text
Using ZeroJ, write a @ZKCircuit proving that a secret balance (64-bit)
is at least a public threshold. Add JUnit 5 tests with one valid witness
and at least two invalid ones (balance below threshold, balance that
overflows 64 bits). Then prove with Groth16Keys and verify with
Groth16BLS12381PureJavaVerifier. Use only APIs from the starter pack.
```

```text
Review this ZeroJ circuit for soundness: list every relation the
application relies on and point to the constraint that enforces it.
Flag any value that is computed but never constrained, any ZkUInt
without @UInt(bits), and any Java control flow over secret values.
```

```text
I verify this proof on Cardano with ZeroJ's on-chain Groth16BLS12381Verifier
validator (org.zeroj.onchain.julc.groth16.validator).
Explain how a third party could replay it, and change the design so the
proof is bound to the spent UTxO and each user can claim only once.
```

## Review what the agent writes

AI assistants make the same mistakes in ZK code that humans do — just faster. Before you trust generated code:

- **Constraints, not just outputs.** A circuit that returns the right answer for honest inputs can still accept a cheater. Insist on invalid-witness tests. See [Test your circuits for soundness](https://zeroj.dev/guides/circuits/testing-circuits/).
- **Ranges.** Every `ZkUInt` needs `@UInt(bits = N)`; field arithmetic wraps around.
- **Curves and hashes.** BLS12-381 and Poseidon with explicit BLS12-381 parameters for anything headed to Cardano.
- **Setup.** `-Dzeroj.allowInsecureTrustedSetup=true` belongs in tests and local demos only. Real keys come from a [ceremony](https://zeroj.dev/guides/proving/trusted-setup-ceremony/).
- **On-chain policy.** A valid proof is not authorization. Check replay protection, nullifiers and `ScriptContext` binding against [Secure your ZK application](https://zeroj.dev/guides/verifying/application-security/).
- **PlonK.** It is experimental in ZeroJ. If an agent picks PlonK, ask why — Groth16 is the supported path.

## What this site does not provide

These are static context files. There is no hosted MCP server, no remote prover and no signing service. Your proofs, witnesses and keys never leave your machine unless your own code sends them somewhere.

## Help improve the context

If your agent keeps getting a ZeroJ pattern wrong, [open an issue](https://github.com/bloxbean/zeroj/issues) with the prompt and the bad output. The fix usually belongs in the starter pack, so the next agent doesn't repeat it.
