# Bundled libblst — provenance & build

> Full build/CI/release guide: [`zeroj-blst/BUILDING.md`](../../../../BUILDING.md).

These `libblst.{so,dylib}` are **built from source** from supranational/blst at a pinned tag
(currently **v0.3.15** — the latest release). supranational publishes **no precompiled binaries**
(source-only), so `zeroj-blst` builds its own — no third-party wrapper, controlled supply chain.

## Rebuild locally (for the current OS/arch)

```bash
zeroj-blst/scripts/build-blst.sh                 # host arch
BLST_TAG=v0.3.15 zeroj-blst/scripts/build-blst.sh
```

Requires `git` + a C toolchain (clang/gcc). The script clones the pinned blst tag, runs its
`build.sh`, links the static archive into a shared library exporting the raw `blst_*` symbols, and
drops it here as `native/<os>/<arch>/libblst.<ext>`.

## All-platform binaries

`.github/workflows/build-blst.yml` runs the same script per runner (Linux/macOS × x86_64/aarch64,
+ Windows) and assembles the all-platform set that ships in the jar. Bump `BLST_TAG` there and in
`build-blst.sh` to update the pinned blst version.

Layout: `native/<os>/<arch>/libblst.<ext>` — `<os>` ∈ {linux, mac, windows},
`<arch>` ∈ {amd64, x86_64, aarch64}. The FFM loader (`BlstFfm`) picks the matching one at runtime.
