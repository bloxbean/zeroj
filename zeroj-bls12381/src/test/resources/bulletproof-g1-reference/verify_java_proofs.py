"""ADR-0061 M2, Java -> Python: checks java-proofs-v1.json with ZeroJ's independent Python implementation.

The file holds proofs made by the Java prover with the spec §7.5 test nonces (JavaProofsFileTest keeps it
current). For every case this script, using only bulletproof_range_reference.py for the cryptography:
  1. recomputes the commitment from (value, blinding) and compares it;
  2. verifies the proof (spec §8) and requires acceptance;
  3. re-proves with the same seed and requires the identical octets;
  4. flips one octet in each proof field and requires rejection.
This glue was written by the Java author; all checks call the reference implementation, which was
written without reading Java. Run:  python3 -I -B verify_java_proofs.py
"""
import sys

sys.dont_write_bytecode = True

import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _import_reference():
    spec = importlib.util.spec_from_file_location("bulletproof_range_reference",
                                                  os.path.join(HERE, "bulletproof_range_reference.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    bp = _import_reference()
    with open(os.path.join(HERE, "java-proofs-v1.json"), encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["schema"] == "zeroj-java-range-proofs-v1"
    assert doc["protocolId"] == "bulletproof-range-bls12-381-g1-v1"
    failures = 0
    tampers = 0
    for c in doc["cases"]:
        n, v, gamma = int(c["bits"]), int(c["value"]), int(c["blinding"])
        ctx = bytes.fromhex(c["ctxHex"])
        V = bytes.fromhex(c["commitmentHex"])
        proof = bytes.fromhex(c["proofHex"])
        problems = []
        reproof, trace = bp._prove_with_test_nonces(v, gamma, n, ctx, bytes.fromhex(c["nonceSeedHex"]))
        if trace["commitment"] != V:
            problems.append("commitment differs")
        if reproof != proof:
            problems.append("re-proof differs")
        outcome = bp.classify(V, proof, n, ctx)
        if outcome != ("true", "accept"):
            problems.append("verdict " + repr(outcome))
        k = {16: 4, 32: 5, 64: 6}[n]
        offsets = [48 * i for i in range(4)] + [192 + 32 * i for i in range(3)] \
            + [288 + 48 * i for i in range(2 * k)] + [len(proof) - 64, len(proof) - 32]
        for off in offsets:
            bad = bytearray(proof)
            bad[off + 7] ^= 0x01
            tampers += 1
            if bp.classify(V, bytes(bad), n, ctx)[0] == "true":
                problems.append("tamper at %d accepted" % off)
        print(("ok   " if not problems else "FAIL ") + c["id"] + ("" if not problems else ": " + "; ".join(problems)))
        failures += bool(problems)
    print("%d cases, %d tampers, %d failing" % (len(doc["cases"]), tampers, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
