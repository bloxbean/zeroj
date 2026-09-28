# ZeroJ documentation site

Astro + Starlight source for **https://zeroj.dev**. It follows the same layout as the Yano
(`getyano.dev`) and JuLC (`julc.dev`) sites: a bespoke landing page, Starlight docs, and AI-ready
exports.

## Work locally

Use Node.js 22.12+ (CI uses Node 24; some transitive dependencies prefer 22.19+) and npm:

```bash
cd www
npm ci
npm run dev        # http://localhost:4321 — also serves /llms.txt and /ai/* live
```

Before opening a PR:

```bash
npm run check      # astro check + verify every Java snippet against the ZeroJ sources
npm run build      # static site + AI artifacts + link/anchor/token/checksum verification
```

No Java build, Gradle, Yaci DevKit or snarkjs is needed to build the site. The build reads a few
files from the repository (see below), so run it from a full checkout.

## Layout

| Path | What it is |
| --- | --- |
| `src/pages/index.astro`, `src/styles/landing.css` | The landing page (standalone, light "Paper" palette; code windows stay dark). |
| `src/content/docs/` | Documentation pages, organized by sidebar section: `start/`, `learn/`, `tutorials/`, `guides/{circuits,proving,verifying,credentials}/`, `use-cases/`, `reference/`, `ai/`. |
| `src/components/walkthrough/` | Interactive use-case walkthroughs (`VotingWalkthrough`, `DisclosureWalkthrough`): actors, messages, who-sees-what views, step narration and a fullscreen **Present** mode. `engine.ts` drives steps from `data-show` / `data-hl` / `data-bad` attributes; `walkthrough.css` holds the shared look. Components are named `*Walkthrough` (stepped flows), `*Explainer` (one-screen interactive ideas) or `*Diagram` (clickable pictures). A page embeds one as `<Name />` (the page must be `.mdx`); the Markdown export replaces it with a one-line note. When an illustration replaces an ASCII diagram, wrap the diagram in `<TextOnly>` (`src/components/TextOnly.astro`): hidden on the web page, kept in the Markdown exports for AI readers. |
| `src/components/SiteTitle.astro`, `DocTitle.astro` | Starlight overrides: brand header, and **View Markdown / Copy page for AI** under each page title. |
| `src/styles/docs.css` | Starlight theme (ink `#080b12`, teal `#2dd4bf`, violet `#8b5cf6`). |
| `release.json` | The released versions the docs install: `zeroj`, and the `julc` and `ccl` versions that release was built with, plus `released`. Updated by hand after each release (see [Releasing](#releasing)). |
| `site.config.mjs` | Site URL and versions (read from `release.json`; the development version from `gradle.properties` goes only into `/ai/manifest.json`). |
| `scripts/remark-versions.mjs` | Replaces `%ZEROJ_VERSION%`, `%JULC_VERSION%`, `%CCL_VERSION%`, `%SITE_URL%` in pages and code blocks. |
| `scripts/ai-artifacts.mjs`, `ai-integration.mjs` | Generates the AI artifacts at build time (and serves them in `astro dev`). |
| `scripts/circuit-catalog.mjs` | Extracts the symbolic circuit API (annotations, `Zk*` types, gadget adapters) from the Java sources. |
| `scripts/check-api-refs.mjs` | Fails if a Java snippet references a ZeroJ type, import, static method or constant that doesn't exist. |
| `scripts/check-site.mjs` | Post-build checks: links, anchors, leftover tokens, Markdown twins, llms.txt targets, manifest checksums, and GitHub links into this repo. |
| `public/` | Logo, favicons, social card, `CNAME`, `robots.txt`. |

## Writing pages

- Every page needs `title` and `description` frontmatter (they feed search and `llms.txt`), and
  `sidebar.order` for its position in the section.
- Prefer `.md`; use `.mdx` only for Starlight components (`Steps`, `Tabs`, `CardGrid`, `LinkCard`…).
- Never hardcode the current version: write `%ZEROJ_VERSION%` (and friends). The build fails on a leftover token.
  Historical facts ("from 0.1.0-pre12 the group is `org.zeroj`") stay literal.
- Every class and method in a Java block must exist — `npm run check` enforces it for ZeroJ APIs.
  Snippets the tutorials present as runnable were compiled and run against the published artifacts.
- Keep maturity claims aligned with the support matrix in the root `README.md`. Groth16 on
  BLS12-381 is the supported path; PlonK is experimental and must not be presented as correct or
  recommended.
- Link to ADRs and other repository files with absolute `https://github.com/bloxbean/zeroj/blob/main/…`
  URLs; `check-site` verifies the path exists in this checkout.

## AI-ready artifacts

Generated on every build (nothing is committed):

| URL | Content |
| --- | --- |
| `/llms.txt` | Curated index ([llmstxt.org](https://llmstxt.org/)) with the key facts agents must not get wrong. |
| `/llms-full.txt` | All pages concatenated as one Markdown file. |
| `/ai/pages/<slug>.md` | A Markdown twin of each page (used by **View Markdown** / **Copy page for AI**). |
| `/ai/starter-pack.md` | The AI Starter Pack, ready to save as `CLAUDE.md` / `AGENTS.md`, with the generated circuit API catalog injected. |
| `/ai/catalog.json` | The circuit API catalog as JSON. |
| `/ai/manifest.json` | Versions, source revision and SHA-256 of every exported file. |

`npm run generate` writes the same files to `.ai-preview/` for inspection.

## Deployment

`.github/workflows/docs.yml` builds PRs that touch `www/**` or `gradle.properties`, checks
`release.json` against Maven Central, and uploads the built site as an artifact. Pushes to `main`
publish `www/dist` to the `gh-pages` branch with `CNAME` `zeroj.dev`, from the `release-staging`
environment. The site also reads ZeroJ's Java sources; after changing those, run the workflow
manually.

One-time setup: in **Settings → Pages** choose **Deploy from a branch** → `gh-pages` / `(root)`,
set the custom domain to `zeroj.dev`, and enable HTTPS. To use a different domain, change
`SITE_URL` in `site.config.mjs`, `public/CNAME`, `public/robots.txt`, and `cname:` in the workflow.

## Releasing

The docs show the versions in `release.json`, not main's `gradle.properties` (which is usually the
next, unpublished version). After a release:

1. Wait until `publish-central.yml` has succeeded and the version is listed in
   `https://repo1.maven.org/maven2/org/zeroj/zeroj-bom-core/maven-metadata.xml`.
2. In `release.json`, set `zeroj` to it, `julc` and `ccl` to the versions that release was built
   with (`zeroj-onchain-julc/build.gradle` and root `build.gradle` at the release tag), and
   `"released": true`.
3. Run `npm run check:release`. It fails if a version isn't on Maven Central, or if `julc`/`ccl`
   don't match the published `zeroj-onchain-julc` POM. The docs CI runs the same check.
4. Merge. Any change under `www/` rebuilds and redeploys the site.

While `released` is `false`, the Installation and Quickstart pages and the landing page say the
pinned version isn't on Maven Central yet.

