import { buildBls12381 } from 'ffjavascript';
// Public generator inputs; no ZeroJ code or output is consumed.
const curve = await buildBls12381(true);
try {
    const coefficients = curve.F12.toObject(curve.pairing(curve.G1.one, curve.G2.one));
    process.stdout.write(coefficients.flat(2).map(String).join('\n') + '\n');
} finally {
    await curve.terminate();
}
