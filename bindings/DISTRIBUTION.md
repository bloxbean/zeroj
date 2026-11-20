# Distribution status — local experimental packages

ZeroJ's source and handwritten TypeScript wrappers are MIT licensed. A generated Web Image
also contains compiler/runtime/dependency material. **The whole precompiled image must not be
labelled MIT-only.** All generated bundle packages have `private: true`; `npm pack` is used
for local consumer testing, not npm publication. No package name or npm scope ownership is
asserted by this repository.

The pinned build uses **Oracle GraalVM 25.3.4.1+1.1**, whose supplied `LICENSE.txt` is the
GraalVM Free Terms and Conditions, including Early Adopter terms. Its redistribution clause
contains fee-related restrictions and addresses runtime portions in generated applications.
The generated JavaScript also carries Oracle GPLv2-with-Classpath-Exception headers. Those
headers are preserved; the three launcher edits are identified and dated. The binary is not
being relicensed by the ZeroJ MIT license.

Packaging copies the local toolchain's license/release/legal directory and dependency jar
notices to an ignored `third-party/` directory, with file hashes. This is a conservative source
inventory, not an assertion that every listed component is linked. Source build inputs are
fingerprinted in each manifest; worktree dirtiness is recorded. The package's `DISTRIBUTION.md`
is this document. Compiler outputs and notices are generated locally, not checked into Git.

Before publishing binary packages, establish the exact runtime licensing and corresponding
source obligations for this toolchain and distribution model. Evaluate a source-built Web
Image using an appropriate open-source JDK as an alternative. The pinned upstream
[Web Image build instructions](https://github.com/oracle/graal/blob/7b025988a922a73286d1326e1eddc1ca39d3f569/web-image/README.md)
describe `mx build`; that alternative has **not** been validated here. Oracle's
[licensing information](https://docs.oracle.com/en/graalvm/jdk/25/docs/licensing-information/)
and [FAQ](https://www.graalvm.org/faq/) distinguish product and component terms. This PR does
not resolve commercial redistribution rights by assumption.

Release preparation also requires final artifact/SBOM review, npm scope ownership, trusted
publishing/provenance and security review. None of those is a claim of production readiness.
Local source builds, browser/Node feasibility tests and implementation work continue independently
of npm publication. Do not upload local review tarballs as release artifacts.
