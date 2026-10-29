#!/usr/bin/env python3
"""Machine-extract RFC 9380 test vectors (Appendices J.9.1, J.9.2, J.10.1, J.10.2, K.1, K.2, K.6)
from the RFC text into JSON. No value is computed; every value is copied from the RFC text.

Usage: extract_rfc9380.py <rfc9380.txt> <out-dir>
"""
import json
import re
import sys

SECTIONS = {
    "J.9.1": ("J.9.1.  ", "J.9.2.  "),
    "J.9.2": ("J.9.2.  ", "J.10.  "),
    "J.10.1": ("J.10.1.  ", "J.10.2.  "),
    "J.10.2": ("J.10.2.  ", "Appendix K.  "),
    "K.1": ("K.1.  ", "K.2.  "),
    "K.2": ("K.2.  ", "K.3.  "),
    "K.6": ("K.6.  ", "Acknowledgements"),
}
FILES = {
    "J.9.1": "j9_1_bls12381g1_xmd_sha256_sswu_ro.json",
    "J.9.2": "j9_2_bls12381g1_xmd_sha256_sswu_nu.json",
    "J.10.1": "j10_1_bls12381g2_xmd_sha256_sswu_ro.json",
    "J.10.2": "j10_2_bls12381g2_xmd_sha256_sswu_nu.json",
    "K.1": "k1_expand_message_xmd_sha256.json",
    "K.2": "k2_expand_message_xmd_sha256_long_dst.json",
    "K.6": "k6_expand_message_xof_shake256.json",
}
KEY = re.compile(r"^   (\S+)\s*=\s?(.*)$")
CONT = re.compile(r"^\s{6,}(\+ I \* )?(\S*)$")


def section_lines(text, start, end):
    lines = text.splitlines()
    s = next(i for i, l in enumerate(lines) if l.startswith(start))
    e = next(i for i, l in enumerate(lines) if i > s and l.startswith(end))
    return lines[s + 1:e]


def parse_fields(lines):
    """Return a list of (key, value) with continuation lines joined. Fp2 values become
    [c0, c1] where the RFC writes 'c0 + I * c1'."""
    out = []
    for line in lines:
        if not line.strip():
            out.append(None)
            continue
        m = KEY.match(line)
        if m:
            out.append([m.group(1), [m.group(2).strip()]])
            continue
        c = CONT.match(line)
        if c and out and out[-1] is not None:
            if c.group(1):
                out[-1][1].append(c.group(2))
            else:
                out[-1][1][-1] += c.group(2)
            continue
        raise ValueError("unparsed line: %r" % line)
    return out


def records(fields):
    header, recs, cur = {}, [], None
    for f in fields:
        if f is None:
            continue
        k, v = f
        val = v[0] if len(v) == 1 else v
        if k == "msg":
            cur = {"msg": val}
            recs.append(cur)
        elif cur is None:
            header[k] = val
        else:
            cur[k] = val
    return header, recs


def main():
    text = open(sys.argv[1], encoding="utf-8-sig").read()
    outdir = sys.argv[2]
    for name, (start, end) in SECTIONS.items():
        header, recs = records(parse_fields(section_lines(text, start, end)))
        doc = {"source": "RFC 9380 Appendix " + name, "header": header, "vectors": recs}
        with open("%s/%s" % (outdir, FILES[name]), "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        print(name, len(recs), "vectors", sorted(recs[0].keys()))


if __name__ == "__main__":
    main()
