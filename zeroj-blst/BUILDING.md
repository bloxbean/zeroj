# Building the native `libblst` for `zeroj-blst`

`zeroj-blst` binds [supranational/blst](https://github.com/supranational/blst) via the Java 25 FFM
(Panama) API — no JNI, no third-party wrapper. supranational publishes **no precompiled binaries**
(source-only), so this module **builds `libblst` from source** and bundles the shared libraries as
jar resources under `src/main/resources/native/<os>/<arch>/libblst.<ext>`. The FFM loader
(`ffm/BlstFfm`) extracts the one matching the host at runtime and calls the raw `blst_*` C API
(`blst_p1s_mult_pippenger`, `blst_p2s_mult_pippenger`, …).

**Pinned version:** `v0.3.15` — the release GitHub's `releases/latest` points to (v0.3.16 exists but
is not marked latest). Bump it in **both** `scripts/build-blst.sh` (the `BLST_TAG` default) and
`.github/workflows/build-blst.yml` (the `blst_tag` input default + `env.BLST_TAG`).

---

## 1. Local build (host architecture)

For local development you only need your own OS/arch.

```bash
# from the repo root
zeroj-blst/scripts/build-blst.sh                 # builds the pinned tag for this host
BLST_TAG=v0.3.15 zeroj-blst/scripts/build-blst.sh # or an explicit tag
```

**Requirements:** `git` and a C toolchain (`clang` on macOS, `gcc`/`cc` on Linux).

**What it does:** shallow-clones the pinned blst tag, runs blst's own `build.sh` (→ `libblst.a`),
links the static archive into a shared library that exports all `blst_*` symbols (macOS:
`-Wl,-all_load`; Linux: `-Wl,--whole-archive`), and writes it to
`zeroj-blst/src/main/resources/native/<os>/<arch>/libblst.<ext>`.

> The local script builds **only the host arch**. The other platforms' binaries come from CI
> (section 2). So after a local build, only your platform's bundled binary is fresh.

### Verify the build

```bash
# symbols present (macOS example; use `nm -D` on Linux)
nm -gU zeroj-blst/src/main/resources/native/mac/aarch64/libblst.dylib | grep pippenger

# run the FFM binding tests against the freshly-built binary (correctness, differential vs pure-Java)
./gradlew :zeroj-crypto:test --tests '*BlstFfmMsmTest' --tests '*BlstG2MsmTest' \
                             --tests '*BlstProverBenchTest.blstBackedProof_equalsPureJava'

# opt-in timing (blst MSM / full-prove speedup)
./gradlew :zeroj-crypto:blstSpike
```

(The blst FFM tests live in `zeroj-crypto` with a **test-only** dependency on `zeroj-blst`, so the
main module stays JNI/native-free by default.)

---

## 2. CI build (all platforms)

`.github/workflows/build-blst.yml` builds `libblst` for every target using the **same**
`build-blst.sh`, so local and CI builds are identical.

**Matrix:**

| runner | os / arch |
|---|---|
| `ubuntu-latest` | linux / amd64 |
| `ubuntu-24.04-arm` | linux / aarch64 |
| `macos-13` | mac / x86_64 |
| `macos-14` | mac / aarch64 |

Each `build` job runs `build-blst.sh` and uploads its `libblst.*` as an artifact
(`libblst-<os>-<arch>`). The `assemble` job downloads all of them into the
`resources/native/<os>/<arch>/` tree and uploads a single **`libblst-all-platforms`** artifact — the
complete native set that ships in the jar.

> Windows (`.dll`) is a documented follow-up: blst's `build.sh` runs under MSYS2/git-bash but needs
> different link flags. Add a `windows-latest` matrix entry + a Windows branch in `build-blst.sh`.

---

## 3. Triggering for a release

The workflow is **manual** (`workflow_dispatch`):

1. GitHub → **Actions** → **build-blst** → **Run workflow**.
2. Set **`blst_tag`** (default `v0.3.15`) to the blst version you want.
3. Run. When it finishes, download the **`libblst-all-platforms`** artifact.
4. Unzip it into `zeroj-blst/src/main/resources/native/` (preserving the `<os>/<arch>/` layout),
   **commit** the refreshed binaries, and cut the `zeroj-blst` release. (Alternatively, wire the
   `assemble` job to attach the set to a GitHub release or open a PR — see the comment in the
   workflow.)

To **bump the pinned blst version** for good: change `BLST_TAG` in `scripts/build-blst.sh` and the
defaults in `build-blst.yml`, run the workflow, and commit the new binaries. Note it in
`src/main/resources/native/README.md`.

---

## 4. GraalVM native image

FFM downcalls use constant `FunctionDescriptor`s, so GraalVM registers the downcall stubs at build
time. The bundled config in
`src/main/resources/META-INF/native-image/com.bloxbean.cardano/zeroj-blst/`:

- `native-image.properties` — `--enable-native-access=ALL-UNNAMED` + `-H:IncludeResources` so the
  `libblst` binaries are embedded (and extracted at runtime).
- `resource-config.json` — the resource include patterns.

If a native-image build reports missing Foreign API support, add (experimental):
`-H:+UnlockExperimentalVMOptions -H:+ForeignAPISupport`. On a **plain JVM**, only
`--enable-native-access=ALL-UNNAMED` is needed at run time. A full native-image build is a heavy
CI/manual validation step — not part of the unit-test loop.

---

## 5. Layout reference

```
zeroj-blst/
  scripts/build-blst.sh                      # local + CI build script (pinned BLST_TAG)
  src/main/java/.../blst/ffm/
    BlstFfm.java                              # FFM loader (extract + SymbolLookup)
    BlstG1Msm.java, BlstG2Msm.java            # blst_p1s/p2s_mult_pippenger bindings
  src/main/resources/native/<os>/<arch>/libblst.<ext>   # bundled binaries (from source)
  src/main/resources/native/README.md        # provenance
  src/main/resources/META-INF/native-image/... # GraalVM config
.github/workflows/build-blst.yml             # CI matrix + assemble
```
