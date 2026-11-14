#!/usr/bin/env python3
"""ADR-0061 M2: external algebra check of the Bulletproof range proof against dalek.

One group- and transcript-generic prover/verifier (bulletproof_generic.py) is run
  * on ristretto255 + Merlin with dalek/zkcrypto bulletproofs 5.0.0's generators,
    transcript, IPA base Q = w·B and byte layout (dalek_binding.py), in both directions:
      1. it verifies dalek's published proofs (tests/range_proof.rs) and rejects tampered
         copies;
      2. dalek 5.0.0 (dalek-harness/, Rust) verifies proofs it produced and rejects
         tampered ones;
  * on BLS12-381 G1 + the fiat-shamir-03 SHAKE128 transcript with the spec's generators and
    independent U (bls_binding.py), where it must reproduce the pinned known-answer proof of
    bulletproof-range-bls12-381-g1-v1 byte for byte.

Usage (standard library only):
    python3 -I -B run_dalek_check.py --self-test [--harness PATH] [--require-harness]
        [--rfc9496 PATH] [--dalek-src DIR] [--resources DIR] [--cfrg-dir DIR] [--spec PATH]
    python3 -I -B run_dalek_check.py --regenerate --harness PATH [--dalek-src DIR]

Test use only.  Nothing here is constant-time or handles real secrets.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)   # -I drops the script directory; the sibling modules live here

import bulletproof_generic as bp   # noqa: E402
import merlin                      # noqa: E402
import ristretto255 as r255        # noqa: E402
import dalek_binding as db         # noqa: E402
import bls_binding as bb           # noqa: E402

RESOURCES_DEFAULT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_HARNESS = os.path.join(HERE, "dalek-harness", "target", "release", "zeroj-dalek-harness")

MERLIN_PIN = os.path.join(HERE, "merlin-conformance.json")
DALEK_GENS_PIN = os.path.join(HERE, "dalek-gens.json")
DALEK_HARNESS_PROOFS = os.path.join(HERE, "dalek-harness-proofs.json")
PY_CASES = os.path.join(HERE, "python-proofs-for-dalek.json")

RANGE_PROOF_RS_SHA256 = "d87b7cde288d25212c3cf24957ea100adf04914be6011ca7e2ecc1e9870b29a8"
DIRECTION2_LABEL = b"ZeroJ-M2-dalek-direction-2"
DALEK_TEST_LABEL = b"Deserialize-And-Verify Test"

# Spec / ADR-0061 pinned known-answer proof (n = 16, v = 12345, ctx "hello", seed 00..1f).
KAT = {
    "n": 16,
    "value": 12345,
    "blinding": int("1234567890abcdef" * 4, 16),
    "ctx": b"hello",
    "seed": bytes(range(32)),
    "tag": ("ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_"
            "Shake128_BLS12381/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f"),
    "commitmentHex": "8c64f7f6919d77f06e79c9520d3af99c6064884d1bc3e1d8b97b63f0d2841cce"
                     "045ba9fb77e7080fb5c3dae56624701e",
    "sessionIdHex": "aefa01ae578defec57e942213978543a2e26bdf81ae69ac9e95dd3bda9ec7556",
    "y": 36209000129655033253065255429180358080765337968981070404285725434891481435214,
    "z": 46633051618233588676975911499950183005061894917303926296959925736837968283823,
    "x": 47228359020218805564661947561577753834407574540194626925198606108420299900437,
    "xu": 22143072433137489460645211340386941818930014091100376110692679921738536006978,
    "xj": [17735452590663590884174088837940452346824915976231644005372727082559053307244,
           32939508233770058845369227004198000974479372739028121348871062643559301637578,
           23879541988904653189122953040323391798477936798697311940928051176925699361449,
           41826612228844513380365295144238554927794368972212012150612085629501841288776],
    "proofHex": (
        "adad082dfddd9ed67f1ac22ccc4969c702769d58ba89787a2926cf8c47e5d272f602f9b2fbe8d934cc861b"
        "9a4f537024a7f48ddec6a36c2841d0ca9705e00a7829d2fb4ab35489e38f78049d95b9a9ad26455a25459e"
        "89eb58209867c8fc27faac3886e6dc0a05715afebce3f4539b49577cea41e76a8ff61eeb21b859c25cf41d"
        "a4407c1bf3d4ed2da0c1f1e4b4df18912af42a08f1601d89265c1aa4e349f615ed30d32b2a7d8863643ced"
        "634bb04e3236c966c3d5b39f7f0c9785e622b0046b3b50bcd8a594c77d878381f49008fe1142cafc9bc6e1"
        "c3c33df220f1f0fdf2419ccdb4dbaf404b0a61ba44304561bdf7fdc6fd325240b89fde47ad99a84b320d90"
        "f8d7c62192725f2682f3bebf68f55e0b7662860dc9ace08538fe2af90f8887c36d60e42e7035d6a495baca"
        "385c9bb063eb6331588a5964c52ff5b0bdf2c05146f2aea07094ac66628ad1860215a682c2261fb17700d6"
        "ccfd2013a25519d04a50fe394a95a6b805b4e473625f0d1fd61ba4019f0ef3b56e1764a76ba735ca84cddf"
        "30c5ec832e06b53c724efc73144324b89cd08db9610a9dc7dccb99070df9e3ada009cab374ef6da4220a4f"
        "0372936a35b480afdd212a13739342c19765c3e0beb723fa110839bf3185d75a17b25ceb98143b11d1d9ef"
        "ae7d9773eb3d53b1fa434efd1be991dd8074d6b69ee86a7eba8732b72dd3802f6628588fbe5246aa8011e4"
        "963ce8ecbfde7cd3454dcddb95af1dbc6a5f62cd951b91673fead403b214e52d10a48689df063f06ccb062"
        "ffe409a3bd61f046457372920d4b57717aa48f892922c123bb2f0e85bbd0e970631e7091d664477011d784"
        "28d0475c8671bee756df4c160f5966d3a5b4652f1621994df89e6046c08781470de8e6a7a642ac8e4a72d3"
        "ca88c5e360c2020f2bb603540318bde0a587efac7952d1b11f634f3079f728fb44f75f9aa11a0a287794e5"
        "ac374163b9be164487311f236a4649c132c22f2a088521aa9c6305e07047ba0786d3e680d20c33ebf9e531"
        "bb6588f086"),
}

CFRG_SHAKE_SHA256 = "f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502"


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.section = ""

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"PASS [{self.section}] {name}")
        else:
            self.failed += 1
            print(f"FAIL [{self.section}] {name} {detail}")
        return ok

    def skip(self, name, why):
        self.skipped += 1
        print(f"SKIP [{self.section}] {name}: {why}")

    def run_section(self, title, fn, *args):
        self.section = title
        t0 = time.time()
        try:
            fn(self, *args)
        except Exception:  # an unexpected exception is a counted failure
            self.check("section raised no unexpected exception", False, traceback.format_exc())
        print(f"---- {title}: {time.time() - t0:.1f}s")


def run_harness(harness, *args):
    out = subprocess.run([harness, *args], check=True, capture_output=True, text=True, timeout=600)
    return json.loads(out.stdout)


def harness_available(harness):
    return harness is not None and os.path.isfile(harness) and os.access(harness, os.X_OK)


def flip(b: bytes, pos: int, bit: int = 0) -> bytes:
    x = bytearray(b)
    x[pos] ^= 1 << bit
    return bytes(x)


def field_offsets(n: int, pl: int, sl: int):
    """(name, offset, is_point) for each proof field in layout order."""
    k = n.bit_length() - 1
    out, pos = [], 0
    for nm in ("A", "S", "T1", "T2"):
        out.append((nm, pos, True))
        pos += pl
    for nm in ("t_hat", "tau_x", "mu"):
        out.append((nm, pos, False))
        pos += sl
    for j in range(1, k + 1):
        out.append((f"L_{j}", pos, True))
        pos += pl
        out.append((f"R_{j}", pos, True))
        pos += pl
    out.append(("a", pos, False))
    pos += sl
    out.append(("b", pos, False))
    return out


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------

def sec_generic_isolation(res: Results):
    """The algebra file imports nothing group-, hash- or transcript-specific."""
    src = open(os.path.join(HERE, "bulletproof_generic.py"), encoding="utf-8").read()
    mods = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            mods.add(node.module)
    res.check("bulletproof_generic.py imports only __future__ and dataclasses",
              mods <= {"__future__", "dataclasses"}, str(mods))
    banned = ["hashlib", "shake", "merlin", "ristretto", "bls12", "keccak", "0x73eda753",
              "2**255", "compress("]
    res.check("bulletproof_generic.py names no curve, hash or transcript",
              not any(b in src for b in banned))


def sec_ristretto(res: Results, rfc_path):
    r255.run_self_test(res, rfc_path)
    if rfc_path is None:
        res.skip("RFC 9496 text re-parse and SHA-256", "pass --rfc9496 PATH")


def sec_merlin(res: Results, harness):
    merlin.self_test_keccak(res)
    py = merlin.conformance_outputs()
    pin = json.load(open(MERLIN_PIN, encoding="utf-8"))
    res.check("Merlin conformance sequences == merlin 3.0.0 outputs pinned in merlin-conformance.json",
              py == pin["outputs"])
    res.check("merlin equivalence_simple challenge",
              py["equivalence_simple"] == pin["outputs"]["equivalence_simple"],
              py["equivalence_simple"])
    if harness_available(harness):
        live = run_harness(harness, "merlin-vectors")
        res.check("Merlin conformance == live merlin 3.0.0 (dalek-harness merlin-vectors)", py == live)
    else:
        res.skip("live merlin 3.0.0 comparison", "harness binary not available")


def sec_dalek_gens(res: Results, st, harness):
    pin = json.load(open(DALEK_GENS_PIN, encoding="utf-8"))
    B, Bb = db.pedersen_gens()
    res.check("PedersenGens::default().B == RFC 9496 generator", r255.encode(B) == r255.GENERATOR_ENCODING)
    res.check("PedersenGens::default().B_blinding == dalek (pinned)", r255.encode(Bb).hex() == pin["B_blinding"])
    res.check("BulletproofGens(64,1) G_0..G_63 == dalek (pinned)",
              [r255.encode(g).hex() for g in st.G_vec] == pin["G"])
    if harness_available(harness):
        live = run_harness(harness, "gens")
        res.check("dalek-gens.json == live dalek 5.0.0 (dalek-harness gens)", live == {k: pin[k] for k in live})
    else:
        res.skip("live dalek generator comparison", "harness binary not available")
    print("NOTE [dalek-generators] H_0..H_63 are not exported by dalek (BulletproofGensShare::H is "
          "pub(crate)); they are checked only through the direction-1 and direction-2 verifications")


def _d1_tampers(st, label, V_bytes, proof_bytes, n, other_V):
    """Yield (name, label, V, proof, n) tampered variants."""
    for nm, off, is_point in field_offsets(n, 32, 32):
        yield (f"flip {nm}", label, V_bytes, flip(proof_bytes, off + (1 if is_point else 0)), n)
    yield ("wrong V", label, other_V, proof_bytes, n)
    yield ("wrong transcript label", b"Deserialize-And-Verify Tesu", V_bytes, proof_bytes, n)
    yield ("truncated by 32 octets", label, V_bytes, proof_bytes[:-32], n)
    if n * 2 <= 64:
        yield (f"verified at n = {2 * n}", label, V_bytes, proof_bytes, 2 * n)
    swapped = bytearray(proof_bytes)
    o = 7 * 32
    swapped[o:o + 32], swapped[o + 32:o + 64] = proof_bytes[o + 32:o + 64], proof_bytes[o:o + 32]
    yield ("L_1 and R_1 swapped", label, V_bytes, bytes(swapped), n)


def sec_direction1(res: Results, st, dalek_src, harness):
    tp = db.load_test_proofs()
    if dalek_src:
        rs = os.path.join(dalek_src, "tests", "range_proof.rs")
        raw = open(rs, "rb").read()
        res.check("tests/range_proof.rs SHA-256 pinned", hashlib.sha256(raw).hexdigest() == RANGE_PROOF_RS_SHA256)
        ex = db.extract_test_proofs(raw.decode("utf-8"))
        res.check("dalek-test-proofs.json == re-extraction from tests/range_proof.rs",
                  all(ex[k] == tp[k] for k in ("label", "commitmentHex", "proofs", "allCommitments")))
    else:
        res.skip("re-extraction from tests/range_proof.rs", "pass --dalek-src DIR")
    label = tp["label"].encode()
    V_bytes = bytes.fromhex(tp["commitmentHex"])
    other_V = bytes.fromhex(tp["allCommitments"][1])
    res.check("published proofs cover m = 1 at n = 8, 16, 32, 64",
              [p["n"] for p in tp["proofs"]] == [8, 16, 32, 64])
    for p in tp["proofs"]:
        n = p["n"]
        pb = bytes.fromhex(p["proofHex"])
        ok, layer, r = db.verify_bytes(st, label, V_bytes, pb, n)
        res.check(f"dalek published proof n={n} (proofs[{(n // 8).bit_length() - 1}][0], vc[0]) accepted, "
                  f"check1 and check2 separately", ok and r.check1 and r.check2, layer)
        if r is not None:
            V = r255.decode(V_bytes)
            res.check(f"n={n} recursive Protocol 1/2 cross-check of check 2",
                      bp.verify_ipa_recursive(st, V, db.CODEC.decode(pb, n), n, r.challenges))
        rejected, total, detail = 0, 0, []
        for name, lab, Vb, prb, nn in _d1_tampers(st, label, V_bytes, pb, n, other_V):
            total += 1
            ok2, layer2, _ = db.verify_bytes(st, lab, Vb, prb, nn)
            if not ok2:
                rejected += 1
            else:
                detail.append(name)
            print(f"      n={n} tamper '{name}': {'rejected at ' + layer2 if not ok2 else 'ACCEPTED'}")
        res.check(f"n={n} all {total} tampered copies rejected", rejected == total, str(detail))
    # Extra: proofs made by dalek 5.0.0 itself through the harness (ChaCha seeds), pinned.
    hp = json.load(open(DALEK_HARNESS_PROOFS, encoding="utf-8"))
    for c in hp["proofs"]:
        ok, layer, r = db.verify_bytes(st, DALEK_TEST_LABEL, bytes.fromhex(c["commitmentHex"]),
                                       bytes.fromhex(c["proofHex"]), c["n"])
        res.check(f"dalek-harness proof n={c['n']} v={c['value']} accepted", ok, layer)
    if harness_available(harness):
        same = all(run_harness(harness, "prove", str(c["n"]), str(c["value"]), str(c["seedByte"])) == c
                   for c in hp["proofs"])
        res.check("dalek-harness-proofs.json == live dalek 5.0.0 prove_single_with_rng (ChaCha seeds)", same)
    else:
        res.skip("live regeneration of dalek-harness-proofs.json", "harness binary not available")


DIR2_VALUES = {8: [0, 1, 255, 0x5a], 16: [0, 1, 65535, 12345], 32: [0, 1, 2 ** 32 - 1, 3141592653],
               64: [0, 1, 2 ** 64 - 1, 0x0123456789abcdef]}


def build_direction2_cases(st):
    cases = []
    for n, values in DIR2_VALUES.items():
        for v in values:
            seed = b"n%d-v%d" % (n, v)
            gamma = db.ShakeNonces(b"gamma/" + seed)()
            V, pr, _ = bp.prove_with_restarts(st, lambda: db.DalekTranscript(DIRECTION2_LABEL), v, gamma, n,
                                              lambda: db.ShakeNonces(seed))
            pb = db.CODEC.encode(pr)
            Vh = r255.encode(V).hex()
            base = {"n": n, "label": DIRECTION2_LABEL.decode(), "commitmentHex": Vh}
            cases.append(dict(base, id=f"n{n}-v{v}", proofHex=pb.hex(), expect="ok"))
            if v in (0, 2 ** n - 1):
                for nm, off, is_point in field_offsets(n, 32, 32):
                    cases.append(dict(base, id=f"n{n}-v{v}-flip-{nm}",
                                      proofHex=flip(pb, off + (1 if is_point else 0)).hex(), expect="reject"))
                a_off = field_offsets(n, 32, 32)[-2][1]
                a_plus = r255.scalar_to_bytes(pr.a + 1)
                cases.append(dict(base, id=f"n{n}-v{v}-a-plus-1",
                                  proofHex=(pb[:a_off] + a_plus + pb[a_off + 32:]).hex(), expect="reject"))
                other = r255.encode(r255.point_add(V, r255.GENERATOR)).hex()
                cases.append(dict(base, id=f"n{n}-v{v}-V-plus-B", commitmentHex=other,
                                  proofHex=pb.hex(), expect="reject"))
                cases.append(dict(base, id=f"n{n}-v{v}-other-label", label=DALEK_TEST_LABEL.decode(),
                                  proofHex=pb.hex(), expect="reject"))
                if n < 64:
                    cases.append(dict(base, id=f"n{n}-v{v}-at-n{2 * n}", n=2 * n, proofHex=pb.hex(),
                                      expect="reject"))
                cases.append(dict(base, id=f"n{n}-v{v}-truncated", proofHex=pb[:-32].hex(), expect="reject"))
    # Positive control: dalek's own published n = 8 proof through the same harness path.
    tp = db.load_test_proofs()
    cases.append({"id": "control-dalek-published-n8", "n": 8, "label": tp["label"],
                  "commitmentHex": tp["commitmentHex"], "proofHex": tp["proofs"][0]["proofHex"],
                  "expect": "ok"})
    return cases


def sec_direction2(res: Results, st, harness):
    pinned = json.load(open(PY_CASES, encoding="utf-8"))
    cases = build_direction2_cases(st)
    res.check("python-proofs-for-dalek.json regenerated byte for byte (deterministic test nonces)",
              cases == pinned["cases"])
    honest = [c for c in cases if c["expect"] == "ok" and not c["id"].startswith("control")]
    res.check(f"{len(honest)} honest proofs (n = 8, 16, 32, 64; incl. v = 0 and 2^n - 1)",
              len(honest) == 16 and {c["n"] for c in honest} == {8, 16, 32, 64})
    self_ok = True
    for c in cases:
        ok, layer, _ = db.verify_bytes(st, c["label"].encode(), bytes.fromhex(c["commitmentHex"]),
                                       bytes.fromhex(c["proofHex"]), c["n"]) \
            if c["n"] in db.ALLOWED_N else (False, "configuration", None)
        self_ok &= (ok == (c["expect"] == "ok"))
    res.check("the generic verifier (dalek binding) agrees with every expectation", self_ok)
    if not harness_available(harness):
        res.skip("dalek 5.0.0 verify_single on Python proofs", "harness binary not available")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cases, fh)
        path = fh.name
    try:
        out = run_harness(harness, "verify", path)
    finally:
        os.unlink(path)
    verdict = {o["id"]: o["verdict"] for o in out}
    n_ok = n_rej = 0
    bad = []
    for c in cases:
        v = verdict.get(c["id"])
        if c["expect"] == "ok":
            if v == "ok":
                n_ok += 1
            else:
                bad.append((c["id"], v))
        else:
            if v is not None and v != "ok":
                n_rej += 1
            else:
                bad.append((c["id"], v))
    total_ok = sum(1 for c in cases if c["expect"] == "ok")
    total_rej = len(cases) - total_ok
    print(f"      dalek accepted {n_ok}/{total_ok} expected-ok, rejected {n_rej}/{total_rej} tampered")
    res.check(f"dalek 5.0.0 verify_single accepts all {total_ok} honest Python proofs (+ control)",
              n_ok == total_ok, str(bad))
    res.check(f"dalek 5.0.0 rejects all {total_rej} tampered Python proofs", n_rej == total_rej, str(bad))


def sec_cfrg_sponge(res: Results, cfrg_dir):
    path = os.path.join(cfrg_dir, "fiatShamirShake128Vectors.json")
    if not os.path.isfile(path):
        res.skip("fiat-shamir-03 B.2 SHAKE128 vectors", f"not found at {path}")
        return
    raw = open(path, "rb").read()
    res.check("fiatShamirShake128Vectors.json SHA-256 == spec 10 pin",
              hashlib.sha256(raw).hexdigest() == CFRG_SHAKE_SHA256)
    n = 0
    for e in json.loads(raw):
        f = e["Function"]
        if f == "DuplexSponge" or f == "DecodeUint":
            ds = bb.DuplexSponge(bytes.fromhex(e["SessionId"]))
            out = b""
            for op in e["Operations"]:
                if op["type"] == "absorb":
                    ds.absorb(bytes.fromhex(op["data"]))
                else:
                    out += ds.squeeze(op["length"])
            ok = out.hex() == e["Output"]
            if f == "DecodeUint":
                ok &= (int.from_bytes(out, "little") % int(e["Modulus"], 16)) == int(e["Challenge"], 16)
        elif f == "DeriveSessionID":
            ok = bb.derive_session_id(bytes.fromhex(e["Tag"])).hex() == e["Output"]
        else:
            continue
        n += 1
        res.check(f"fiat-shamir-03 {e['Id']}", ok)
    res.check("11 sponge vectors run (B.2.1-B.2.11)", n == 11, str(n))


def sec_bls_kat(res: Results, spec_path):
    t0 = time.time()
    st, d_gens = bb.setup()
    print(f"      BLS12-381 setup (129 strict decodes + basis): {time.time() - t0:.1f}s")
    res.check("D_gens == spec Appendix A pin", d_gens.hex() == bb.D_GENS_PIN, d_gens.hex())
    res.check("G, H == pedersen-bls12-381-g1-v1 2.2 pins",
              bb.C.compress(st.B).hex() == bb.G_PIN and bb.C.compress(st.B_blind).hex() == bb.H_PIN)
    if spec_path and os.path.isfile(spec_path):
        import re
        text = open(spec_path, encoding="utf-8").read()
        rows = re.findall(r"^\| `((?:G|H)_\d+|U)` \| `([0-9a-f]{96})` \|$", text, re.M)
        _, _, _, _, gj = bb.load_generators()
        res.check("spec Appendix A table == generators-v1.json (129 encodings, same order)",
                  [(r[0], r[1]) for r in rows] == [(g["name"], g["compressedHex"]) for g in gj["generators"]])
    else:
        res.skip("spec Appendix A table comparison", "pass --spec PATH")

    tr = bb.SpecTranscript(KAT["ctx"], st.B, st.B_blind, d_gens)
    res.check("session tag == spec 5.1 example", bb.session_tag(16, KAT["ctx"]).decode() == KAT["tag"])
    V, pr, trace = bp.prove(st, tr, KAT["value"], KAT["blinding"], KAT["n"], bb.test_nonces(KAT["seed"]))
    pb = bb.codec().encode(pr)
    res.check("commitment V == pinned commitmentHex", bb.C.compress(V).hex() == KAT["commitmentHex"])
    res.check("session id == pinned sessionIdHex", tr.session_id.hex() == KAT["sessionIdHex"])
    res.check("instance is 244 octets", len(tr.instance) == 244)
    res.check("challenges y, z, x, x_u, x_1..x_4 == pinned",
              (trace["y"], trace["z"], trace["x"], trace["ipa_base"], trace["x_j"])
              == (KAT["y"], KAT["z"], KAT["x"], KAT["xu"], KAT["xj"]))
    res.check("generic prover reproduces the pinned 736-octet proof byte for byte",
              pb.hex() == KAT["proofHex"], pb.hex()[:32])
    ok, layer, r = bb.verify_bytes(st, d_gens, KAT["ctx"], bytes.fromhex(KAT["commitmentHex"]),
                                   bytes.fromhex(KAT["proofHex"]), 16)
    res.check("generic verifier accepts the pinned proof (check1 and check2)", ok and r.check1 and r.check2, layer)
    if r is not None:
        res.check("recursive Protocol 1/2 cross-check of check 2 (BLS12-381)",
                  bp.verify_ipa_recursive(st, V, bb.codec().decode(pb, 16), 16, r.challenges))
    kp = bytes.fromhex(KAT["proofHex"])
    offs = {nm: off for nm, off, _ in field_offsets(16, 48, 32)}
    tampers = [
        ("t_hat + 1 in its last octet", flip(kp, offs["t_hat"] + 31), b"hello", 16, "check1"),
        ("a last octet flipped", flip(kp, offs["a"] + 31), b"hello", 16, "check2"),
        ("ctx 'hellp'", kp, b"hellp", 16, None),
        ("verified at n = 32", kp, b"hello", 32, "length"),
    ]
    for name, prb, ctx, n, want_layer in tampers:
        ok2, layer2, _ = bb.verify_bytes(st, d_gens, ctx, bytes.fromhex(KAT["commitmentHex"]), prb, n)
        res.check(f"tampered KAT rejected: {name} (layer {layer2})",
                  (not ok2) and (want_layer is None or layer2 == want_layer))


def self_test(args):
    res = Results()
    harness = args.get("--harness", DEFAULT_HARNESS)
    resources = args.get("--resources", RESOURCES_DEFAULT)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(resources))))
    cfrg_dir = args.get("--cfrg-dir", os.path.join(
        repo_root, "zeroj-test-vectors", "src", "main", "resources", "test-vectors", "cfrg-drafts-03"))
    spec = args.get("--spec", os.path.join(repo_root, "docs", "specs", "bulletproof-range-bls12-381-g1-v1.md"))
    print(f"harness: {harness} ({'available' if harness_available(harness) else 'NOT available'})")
    print(f"resources: {resources}")
    res.run_section("generic-core", sec_generic_isolation)
    res.run_section("ristretto255", sec_ristretto, args.get("--rfc9496"))
    res.run_section("merlin", sec_merlin, harness)
    st = db.setup()
    res.run_section("dalek-generators", sec_dalek_gens, st, harness)
    res.run_section("direction-1", sec_direction1, st, args.get("--dalek-src"), harness)
    res.run_section("direction-2", sec_direction2, st, harness)
    bb.init(resources)
    res.run_section("cfrg-sponge", sec_cfrg_sponge, cfrg_dir)
    res.run_section("bls12-381-tie-in", sec_bls_kat, spec)
    print(f"SUMMARY: {res.passed} passed, {res.failed} failed, {res.skipped} skipped")
    if res.failed:
        return 1
    if res.skipped and "--require-harness" in args and not harness_available(harness):
        print("FAIL: --require-harness given but the harness is not available")
        return 1
    return 0


def regenerate(args):
    harness = args["--harness"]
    st = db.setup()
    m = run_harness(harness, "merlin-vectors")
    json.dump({"source": "merlin 3.0.0 via dalek-harness merlin-vectors", "outputs": m},
              open(MERLIN_PIN, "w"), indent=1)
    g = run_harness(harness, "gens")
    g["source"] = "bulletproofs 5.0.0 PedersenGens::default(), BulletproofGens::new(64, 1).share(0).G(64)"
    json.dump(g, open(DALEK_GENS_PIN, "w"), indent=1)
    if "--dalek-src" in args:
        rs = os.path.join(args["--dalek-src"], "tests", "range_proof.rs")
        raw = open(rs, "rb").read()
        d = db.extract_test_proofs(raw.decode("utf-8"))
        d["source"] = "bulletproofs-5.0.0/tests/range_proof.rs deserialize_and_verify, proofs[i][0], vc[0..]"
        d["sourceSha256"] = hashlib.sha256(raw).hexdigest()
        json.dump(d, open(db.TEST_PROOFS_PATH, "w"), indent=1)
    hp = []
    for i, n in enumerate((8, 16, 32, 64)):
        for j, v in enumerate((0, 2 ** n - 1)):
            hp.append(run_harness(harness, "prove", str(n), str(v), str(100 + 2 * i + j)))
    json.dump({"source": "bulletproofs 5.0.0 prove_single_with_rng, ChaChaRng::from_seed([seedByte; 32]), "
                         "label b\"Deserialize-And-Verify Test\" (dalek-harness prove)", "proofs": hp},
              open(DALEK_HARNESS_PROOFS, "w"), indent=1)
    cases = build_direction2_cases(st)
    json.dump({"source": "run_dalek_check.py build_direction2_cases (generic prover, dalek binding, "
                         "ShakeNonces test nonces)", "cases": cases}, open(PY_CASES, "w"), indent=1)
    for p in (MERLIN_PIN, DALEK_GENS_PIN, DALEK_HARNESS_PROOFS, PY_CASES):
        with open(p, "a") as fh:
            fh.write("\n")
    print("regenerated")
    return 0


def parse_args(argv):
    out = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--self-test", "--regenerate", "--require-harness"):
            out[a] = True
            i += 1
        else:
            out[a] = argv[i + 1]
            i += 2
    return out


def main(argv):
    args = parse_args(argv)
    if "--regenerate" in args:
        return regenerate(args)
    if "--self-test" in args:
        return self_test(args)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
