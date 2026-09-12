package org.zeroj.crypto.snarkjs;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Package-private writer for the exact text snarkjs v0.7.6 produces for its JSON artifacts, plus
 * the point/scalar egress checks shared by the Groth16 and PlonK exporters (ADR-0047).
 *
 * <p>snarkjs writes every artifact with {@code bfj.write(file, stringifyBigInts(obj), {space: 1})}
 * (bfj 7.1.0, {@code cli.js}): one-space indentation, one value per line, keys in insertion order,
 * field elements as decimal strings, small counts as JSON numbers, <b>no trailing newline</b>, and
 * — unlike {@code JSON.stringify(obj, null, 1)} — an empty container spread over two lines
 * ({@code "[\n]"}, e.g. {@code public.json} of a circuit with no public inputs). The tree handed to
 * {@link #write(Object)} uses {@link Map} (insertion-ordered) for objects, {@link List} for
 * arrays, {@link String} for decimal strings and {@link Integer} for numbers. The output is pinned
 * byte-for-byte against checked-in and freshly generated snarkjs artifacts by the KAT and interop
 * tests.</p>
 *
 * <p>Encodings (snarkjs {@code G1.toObject} / {@code G2.toObject} of an affine point):</p>
 * <ul>
 *   <li>G1: {@code [x, y, "1"]}</li>
 *   <li>G2: {@code [[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]}</li>
 * </ul>
 *
 * <p>Egress checks fail closed with {@link IllegalArgumentException}: no point may be the point at
 * infinity (ADR-0045 forbids infinity in every Groth16 proof/VK position; the single PlonK
 * exception is {@link #g1AllowingInfinity}), every point must be on its curve and in the
 * prime-order subgroup, and every scalar must be canonical in {@code [0, r)}. This is an egress boundary for
 * ZeroJ-produced values, so the checks are a defence against exporter/prover bugs, not a
 * substitute for the verifier's ingress validation on the snarkjs side.</p>
 */
final class SnarkjsJsonWriter {

    private SnarkjsJsonWriter() {}

    static final BigInteger FR_MODULUS = MontFr381.modulus();

    // ------------------------------------------------------------------ formatting

    /** Render {@code tree} exactly as snarkjs' {@code bfj.write(..., {space: 1})} would (no trailing newline). */
    static String write(Object tree) {
        var sb = new StringBuilder(1 << 12);
        writeValue(sb, tree, 0);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v, int depth) {
        if (v instanceof String s) {
            writeString(sb, s);
        } else if (v instanceof Integer i) {
            sb.append(i.intValue());
        } else if (v instanceof List<?> list) {
            sb.append("[\n");   // bfj writes an empty array as "[\n]" (JSON.stringify would write "[]")
            for (int i = 0; i < list.size(); i++) {
                indent(sb, depth + 1);
                writeValue(sb, list.get(i), depth + 1);
                sb.append(i + 1 < list.size() ? ",\n" : "\n");
            }
            indent(sb, depth);
            sb.append(']');
        } else if (v instanceof Map<?, ?> map) {
            sb.append("{\n");   // bfj writes an empty object as "{\n}"
            int i = 0;
            for (var e : map.entrySet()) {
                indent(sb, depth + 1);
                writeString(sb, (String) e.getKey());
                sb.append(": ");
                writeValue(sb, e.getValue(), depth + 1);
                sb.append(++i < map.size() ? ",\n" : "\n");
            }
            indent(sb, depth);
            sb.append('}');
        } else {
            throw new IllegalArgumentException("unsupported JSON tree node: "
                    + (v == null ? "null" : v.getClass().getName()));
        }
    }

    private static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append(' ');
    }

    /** Only the ASCII identifiers/decimals this writer emits; anything else is a programming error. */
    private static void writeString(StringBuilder sb, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || c == '_' || c == '-';
            if (!ok) throw new IllegalArgumentException("non-ASCII-identifier character in JSON string: " + s);
        }
        sb.append('"').append(s).append('"');
    }

    // ------------------------------------------------------------------ encodings

    /** {@code [x, y, "1"]} after full validation (non-infinity, on-curve, in-subgroup). */
    static List<String> g1(String label, AffineG1 p) {
        if (p == null) throw new IllegalArgumentException(label + ": null G1 point");
        if (p.isInfinity()) throw new IllegalArgumentException(label + ": G1 point at infinity is not exportable");
        if (!p.isOnCurve()) throw new IllegalArgumentException(label + ": G1 point is not on BLS12-381");
        // Same subgroup predicate as SetupCacheIO.validateG1 (Montgomery Jacobian [r]P == O); the
        // BigInteger G1Point.isInSubgroup path is ~10x slower and matters for large IC arrays.
        if (!JacobianG1BLS381.fromAffine(p.x(), p.y()).scalarMul(G1Point.R).isInfinity()) {
            throw new IllegalArgumentException(label + ": G1 point is not in the prime-order subgroup");
        }
        return List.of(p.x().toBigInteger().toString(), p.y().toBigInteger().toString(), "1");
    }

    /**
     * {@link #g1(String, AffineG1)}, except that the point at infinity is encoded the way snarkjs'
     * {@code G1.toObject(zero)} writes it: {@code ["0", "1", "0"]}. Only for the PlonK selector
     * commitments {@code Qm/Ql/Qr/Qo/Qc}, which are legitimately the identity when a selector
     * polynomial is identically zero; the ZeroJ PlonK verifier accepts infinity in exactly those
     * five positions and nowhere else, and this exporter mirrors that policy.
     */
    static List<String> g1AllowingInfinity(String label, AffineG1 p) {
        if (p == null) throw new IllegalArgumentException(label + ": null G1 point");
        if (p.isInfinity()) return INFINITY_G1;
        return g1(label, p);
    }

    private static final List<String> INFINITY_G1 = List.of("0", "1", "0");

    /** {@code [[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]} after full validation. */
    static List<List<String>> g2(String label, AffineG2 p) {
        if (p == null) throw new IllegalArgumentException(label + ": null G2 point");
        if (p.isInfinity()) throw new IllegalArgumentException(label + ": G2 point at infinity is not exportable");
        if (!p.isOnCurve()) throw new IllegalArgumentException(label + ": G2 point is not on the BLS12-381 twist");
        if (!JacobianG2BLS381.fromAffine(p.x(), p.y()).scalarMul(G1Point.R).isInfinity()) {
            throw new IllegalArgumentException(label + ": G2 point is not in the prime-order subgroup");
        }
        return List.of(List.of(p.x().reBigInt().toString(), p.x().imBigInt().toString()),
                List.of(p.y().reBigInt().toString(), p.y().imBigInt().toString()),
                List.of("1", "0"));
    }

    /** Canonical scalar in {@code [0, r)} as a decimal string; never reduced silently. */
    static String scalar(String label, BigInteger v) {
        if (v == null) throw new IllegalArgumentException(label + ": null scalar");
        if (v.signum() < 0 || v.compareTo(FR_MODULUS) >= 0) {
            throw new IllegalArgumentException(label + ": scalar is not canonical in [0, r)");
        }
        return v.toString();
    }

    static List<String> scalars(String label, BigInteger[] values) {
        if (values == null) throw new IllegalArgumentException(label + ": null scalar array");
        var out = new ArrayList<String>(values.length);
        for (int i = 0; i < values.length; i++) out.add(scalar(label + "[" + i + "]", values[i]));
        return out;
    }
}
