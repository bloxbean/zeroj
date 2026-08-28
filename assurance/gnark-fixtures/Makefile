# ADR-0044: pinned, non-published gnark fixture generator.
#
# This is NOT a runtime provider. It builds no shared library, exposes no Java FFM API, and is not
# part of the Gradle build or the publication graph. Its only job is to keep the gnark-generated
# PlonK BLS12-381 test vectors in zeroj-test-vectors reproducible, so the Java PlonK verifier keeps
# being checked against an implementation ZeroJ does not control.

GNARK_VERSION := $(shell cat GNARK_VERSION | tr -d '[:space:]')
VECTORS_DIR := ../../zeroj-test-vectors/src/main/resources/test-vectors/plonk-bls12381

.PHONY: check-go version gen gen-scratch clean

check-go:
	@which go > /dev/null 2>&1 || (echo "Error: Go is required. Install from https://golang.org/dl/" && exit 1)
	@echo "Go version: $$(go version)"

version:
	@echo "gnark version: $(GNARK_VERSION)"
	@echo "vectors dir:   $(VECTORS_DIR)"

# Regenerate the committed vectors in place.
#
# The output is NOT byte-reproducible: the PlonK setup uses gnark's `unsafekzg` test SRS, which is
# randomized per run, so every invocation emits a fresh independent proof and a fresh SRS. Do not
# expect a clean `git diff` after running this, and do not treat a difference as a regression.
#
# The assurance property is not "the bytes match". It is: an artifact produced by an implementation
# ZeroJ does not control is still accepted by ZeroJ's pure-Java PlonK verifier, and still derives
# the same Fiat-Shamir challenges. Verify that with the Java side after regenerating:
#
#     make gen
#     (cd ../.. && ./gradlew :zeroj-verifier-plonk:test)
#
# A failure there is a real finding: either ZeroJ's verifier/transcript diverged from gnark, or the
# pinned gnark version changed behavior. Investigate before committing regenerated vectors.
gen: check-go
	go run . -output $(VECTORS_DIR)

# Same, but into a scratch directory, so the committed vectors are left untouched.
gen-scratch: check-go
	@rm -rf build/vectors && mkdir -p build/vectors
	go run . -output build/vectors
	@echo "Fresh gnark $(GNARK_VERSION) vectors written to build/vectors"

clean:
	rm -rf build
