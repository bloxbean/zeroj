# Building the native `libblst` for `zeroj-blst`

`zeroj-blst` binds [supranational/blst](https://github.com/supranational/blst) via the Java 25 FFM
(Panama) API — no JNI, no third-party wrapper or binary (ADR-0062 D3). supranational publishes **no
precompiled binaries** (source-only), so this module **builds `libblst` from source** and bundles
the shared libraries as jar resources under
`src/main/resources/org/zeroj/blst/native/<os>/<arch>/libblst.<ext>`, next to a SHA-256 manifest,
`libblst.sha256`. The FFM loader (`ffm/BlstFfm`) loads only the bundled library for the host, and
only if its SHA-256 matches the manifest; it then calls the raw `blst_*` C API.

**Pinned version:** `v0.3.15`, commit `6d960cd05d6fe2b5bc9ba161edf0c1a131b87c4c`. The build fails if
the tag resolves to any other commit (ADR-0062 D6). To bump it, change **both** `DEFAULT_BLST_TAG`
and `DEFAULT_BLST_COMMIT` in `scripts/build-blst.sh` and the `blst_tag` / `blst_commit` defaults in
`.github/workflows/build-blst.yml`.

---

## 1. Local build

```bash
# from the repo root
zeroj-blst/scripts/build-blst.sh                              # pinned commit, host arch
BLST_TAG=<tag> BLST_COMMIT=<40-hex> zeroj-blst/scripts/build-blst.sh  # a different pin
CC=x86_64-linux-gnu-gcc BLST_TARGET_ARCH=amd64 zeroj-blst/scripts/build-blst.sh  # Linux cross build
```

**Requirements:** `git` and a C toolchain (`clang` on macOS, `gcc`/`cc` on Linux).

**What it does:** shallow-clones the pinned blst tag, checks `git rev-parse HEAD` against the pinned
commit, runs blst's own `build.sh` (→ `libblst.a`), links the static archive into a shared library
exporting all `blst_*` symbols (macOS: `-Wl,-all_load`; Linux: `-Wl,--whole-archive`), writes it to
`src/main/resources/org/zeroj/blst/native/<os>/<arch>/libblst.<ext>`, and regenerates
`libblst.sha256` with `scripts/update-blst-manifest.sh`.

The Linux libraries can be built on a Mac with Docker (`ubuntu:22.04`, glibc 2.35 baseline): run the
script natively in a `linux/arm64` container for aarch64, and cross-compile amd64 in the same
container with `gcc-x86-64-linux-gnu` as shown above.

### Verify the build

```bash
nm -gU zeroj-blst/src/main/resources/org/zeroj/blst/native/mac/aarch64/libblst.dylib | grep pippenger
# (use `nm -D` on Linux)

# provenance gate (manifest, no JNI symbols), binding and MSM tests
./gradlew :zeroj-blst:test :zeroj-crypto-blst:test

# opt-in timing (blst MSM / full-prove speedup)
./gradlew :zeroj-crypto-blst:blstBench
```

`BundledLibblstProvenanceTest` fails if a bundled library is missing from the manifest, does not
match it, or carries the JNI symbols of the former `foundation.icon:blst-java` binary.

---

## 2. CI build (all platforms)

`.github/workflows/build-blst.yml` builds `libblst` for every target with the **same**
`build-blst.sh`.

| runner | os / arch |
|---|---|
| `ubuntu-22.04` | linux / amd64 |
| `ubuntu-22.04-arm` | linux / aarch64 |
| `macos-15` | mac / aarch64 |

Linux runners are pinned to **22.04** (glibc 2.35) so the shared libraries load on older distros.
macOS is **arm64-only**: GitHub retired the free Intel runner. `build-blst.sh` sets
`MACOSX_DEPLOYMENT_TARGET=11.0` (override it in the environment), so the dylib's minimum macOS is 11.0
rather than the build host's version. There is no Windows or macOS x86_64
library; `BlstFfm` rejects those platforms and the pure-Java provider applies.

Each `build` job removes the committed library, runs `build-blst.sh` and uploads `libblst.*` as
`libblst-<os>-<arch>`. The `assemble` job stages all of them, regenerates the manifest, and uploads
**`libblst-all-platforms`** (libraries plus `libblst.sha256`).

The tag release (`release.yml`) rebuilds every library from source and fails if any artifact is
missing or empty; it regenerates the manifest and records each SHA-256 in the GitHub release.

---

## 3. Refreshing the committed binaries

1. GitHub → **Actions** → **build-blst** → **Run workflow** (defaults are the pinned tag and commit).
2. Download **`libblst-all-platforms`** and unzip it into
   `zeroj-blst/src/main/resources/org/zeroj/blst/native/`, preserving `<os>/<arch>/`.
3. Run `zeroj-blst/scripts/update-blst-manifest.sh` and `./gradlew :zeroj-blst:test`, then commit
   the binaries and the manifest together.

---

## 4. GraalVM native image

The bundled config is in `src/main/resources/META-INF/native-image/org.zeroj/zeroj-blst/`. See
`native-image.properties` there for the flags and the status of native-image verification
(ADR-0062 M8).

---

## 5. Layout reference

```
zeroj-blst/
  scripts/build-blst.sh                    # local + CI build (pinned tag + commit)
  scripts/update-blst-manifest.sh          # regenerates libblst.sha256
  src/main/java/org/zeroj/blst/ffm/
    BlstFfm.java                           # loader (manifest check, owner-only temp dir, SymbolLookup)
    BlstCurve.java                         # validated point arithmetic + pairing
    BlstG1Msm.java, BlstG2Msm.java         # blst_p1s/p2s_mult_pippenger bindings
  src/main/resources/org/zeroj/blst/native/<os>/<arch>/libblst.<ext>   # bundled binaries
  src/main/resources/org/zeroj/blst/native/libblst.sha256              # manifest
  src/main/resources/org/zeroj/blst/native/README.md                   # provenance
  src/main/resources/META-INF/native-image/org.zeroj/zeroj-blst/       # GraalVM config
.github/workflows/build-blst.yml           # CI matrix + assemble
```
