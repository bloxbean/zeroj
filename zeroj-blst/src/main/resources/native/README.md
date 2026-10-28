# Bundled libblst — provenance & build

> Full build/CI/release guide: [`zeroj-blst/BUILDING.md`](../../../../BUILDING.md).

These `libblst.{so,dylib}` are **built from source** from supranational/blst, pinned by commit hash
(**v0.3.15**, commit `6d960cd05d6fe2b5bc9ba161edf0c1a131b87c4c`; ADR-0062 D6). The build fails if
the tag resolves to any other commit. supranational publishes **no precompiled binaries**
(source-only), so `zeroj-blst` builds its own — no third-party wrapper, controlled supply chain.

These binaries back every native path in `zeroj-blst`: the MSM, the curve/pairing binding and the
provider (ADR-0062 D3 removed the former prebuilt JNI binary).

## Rebuild locally (for the current OS/arch)

```bash
zeroj-blst/scripts/build-blst.sh                 # host arch, pinned v0.3.15 commit
BLST_TAG=<tag> BLST_COMMIT=<40-hex> zeroj-blst/scripts/build-blst.sh   # a different pin
```

Requires `git` + a C toolchain (clang/gcc). The script clones the pinned blst tag, runs its
`build.sh`, links the static archive into a shared library exporting the raw `blst_*` symbols, and
drops it here as `native/<os>/<arch>/libblst.<ext>`.

## All-platform binaries

> **Releases rebuild these from source**: the `build-blst-native` stage in
> `.github/workflows/release.yml` builds the pinned commit on every platform at tag-release time and
> injects the results before publishing. A missing or empty artifact fails the release (ADR-0062
> D6), so released jars never ship the committed dev binaries below. The SHA-256 of every bundled
> library is attached to the GitHub release.

`.github/workflows/build-blst.yml` runs the same script per runner (Linux amd64/aarch64 on
`ubuntu-22.04`, macOS arm64) and assembles the all-platform set that ships in the jar.
Bump `BLST_TAG` **and** `BLST_COMMIT` there and in `build-blst.sh` to update the pinned blst
version. On macOS arm64 the committed dylib was reproduced bit-for-bit from the pinned commit
(SHA-256 `7be95e24d9629f1b84af74d17fa9ce9a9e97ab7e21ac08d0b54c607683e79971`, 2026-10-28).

Layout: `native/<os>/<arch>/libblst.<ext>` — `<os>` ∈ {linux, mac},
`<arch>` ∈ {amd64, aarch64}. The FFM loader (`BlstFfm`) picks the matching one at runtime. macOS is
**arm64-only** (GitHub retired the free Intel runner in Dec 2025). blst MSM is opt-in acceleration
(`zeroj-crypto-blst`); the default prover backend is pure-Java (`G1MsmBackend.PURE_JAVA`), so Intel
Macs still work — they just can't opt into the blst speedup.
