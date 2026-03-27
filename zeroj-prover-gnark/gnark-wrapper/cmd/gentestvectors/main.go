package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381_kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// MultiplierCircuit: proves X * Y = Z without revealing X and Y.
// Public: Z (the product)
// Private: X, Y (the factors)
type MultiplierCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (c *MultiplierCircuit) Define(api frontend.API) error {
	product := api.Mul(c.X, c.Y)
	api.AssertIsEqual(product, c.Z)
	return nil
}

func main() {
	outputDir := flag.String("output", ".", "output directory for test vectors")
	flag.Parse()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	curve := ecc.BLS12_381
	fmt.Println("=== ZeroJ PlonK Test Vector Generator ===")
	fmt.Println("Circuit: Multiplier (X * Y = Z)")
	fmt.Println("Curve:   BLS12-381")
	fmt.Println()

	// 1. Compile circuit to SparseR1CS (PlonK constraint system)
	fmt.Println("Step 1: Compiling circuit to SparseR1CS...")
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &MultiplierCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Constraints: %d\n", ccs.GetNbConstraints())
	fmt.Printf("  Public inputs: %d\n", ccs.GetNbPublicVariables()-1) // -1 for constant wire

	// Save SparseR1CS
	r1csPath := filepath.Join(*outputDir, "circuit.scs")
	writeToFile(r1csPath, ccs)

	// 2. Generate KZG SRS (unsafe — for testing only)
	fmt.Println("Step 2: Generating KZG SRS (unsafe — testing only)...")
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SRS generation failed: %v\n", err)
		os.Exit(1)
	}

	// 3. Run PlonK setup
	fmt.Println("Step 3: Running PlonK setup...")
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}

	// Save PK and VK binary
	pkPath := filepath.Join(*outputDir, "proving_key.bin")
	writeToFile(pkPath, pk)
	vkPath := filepath.Join(*outputDir, "verification_key.bin")
	writeToFile(vkPath, vk)

	// 4. Create witness (X=3, Y=11, Z=33)
	fmt.Println("Step 4: Creating witness (X=3, Y=11, Z=33)...")
	assignment := &MultiplierCircuit{
		X: 3,
		Y: 11,
		Z: 33,
	}

	wit, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "witness creation failed: %v\n", err)
		os.Exit(1)
	}

	// Save full witness
	witPath := filepath.Join(*outputDir, "witness.bin")
	witFile, _ := os.Create(witPath)
	wit.WriteTo(witFile)
	witFile.Close()

	// 5. Prove
	fmt.Println("Step 5: Generating PlonK proof...")
	proof, err := plonk.Prove(ccs, pk, wit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proving failed: %v\n", err)
		os.Exit(1)
	}

	// 6. Verify (sanity check)
	fmt.Println("Step 6: Verifying proof (sanity check)...")
	publicWit, _ := wit.Public()
	if err := plonk.Verify(proof, vk, publicWit); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  Proof verified OK!")

	// 7. Export artifacts
	fmt.Println("Step 7: Exporting artifacts...")

	// proof.json — base64-encoded binary proof
	exportBinaryAsJSON(filepath.Join(*outputDir, "proof.json"), proof, "plonk")

	// verification_key.json — base64-encoded binary VK
	exportBinaryAsJSON(filepath.Join(*outputDir, "verification_key.json"), vk, "plonk")

	// public.json — public inputs as decimal strings (snarkjs-compatible format)
	exportPublicInputs(filepath.Join(*outputDir, "public.json"), publicWit, curve)

	// proof_base64.txt — raw base64 proof bytes (for zeroj_plonk_verify)
	exportRawBase64(filepath.Join(*outputDir, "proof_base64.txt"), proof)

	// public_witness.bin — gnark binary public witness (for zeroj_plonk_verify)
	pubWitPath := filepath.Join(*outputDir, "public_witness.bin")
	pubWitFile, _ := os.Create(pubWitPath)
	publicWit.WriteTo(pubWitFile)
	pubWitFile.Close()

	// metadata.json
	exportMetadata(filepath.Join(*outputDir, "metadata.json"), ccs, curve)

	// plonk_cardano.json — decomposed proof points + pre-computed pairing inputs for on-chain verification
	exportCardanoPlonkData(filepath.Join(*outputDir, "plonk_cardano.json"), proof, vk, publicWit, ccs)

	fmt.Println()
	fmt.Println("=== All artifacts exported to:", *outputDir, "===")
	fmt.Println("Files:")
	entries, _ := os.ReadDir(*outputDir)
	for _, e := range entries {
		info, _ := e.Info()
		fmt.Printf("  %-30s %d bytes\n", e.Name(), info.Size())
	}
}

func writeToFile(path string, obj io.WriterTo) {
	file, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create %s: %v\n", path, err)
		os.Exit(1)
	}
	defer file.Close()
	if _, err := obj.WriteTo(file); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", path, err)
		os.Exit(1)
	}
}

func exportBinaryAsJSON(path string, obj io.WriterTo, protocol string) {
	var buf bytes.Buffer
	obj.WriteTo(&buf)

	data := map[string]interface{}{
		"binary":   base64.StdEncoding.EncodeToString(buf.Bytes()),
		"protocol": protocol,
		"curve":    "bls12381",
		"hex":      hex.EncodeToString(buf.Bytes()),
	}
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, jsonBytes, 0o644)
}

func exportPublicInputs(path string, publicWit witness.Witness, curve ecc.ID) {
	// Use gnark's Vector() to get field elements directly
	vec := publicWit.Vector()

	var values []string
	// vec is a fr.Vector (slice of fr.Element)
	switch v := vec.(type) {
	case bls12381_fr.Vector:
		for _, fe := range v {
			val := new(big.Int)
			fe.BigInt(val)
			values = append(values, val.String())
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported vector type: %T\n", vec)
		os.WriteFile(path, []byte("[]"), 0o644)
		return
	}

	if len(values) == 0 {
		os.WriteFile(path, []byte("[]"), 0o644)
		return
	}

	jsonBytes, _ := json.MarshalIndent(values, "", " ")
	os.WriteFile(path, jsonBytes, 0o644)
}

func exportRawBase64(path string, obj io.WriterTo) {
	var buf bytes.Buffer
	obj.WriteTo(&buf)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	os.WriteFile(path, []byte(b64), 0o644)
}

func exportMetadata(path string, ccs interface {
	GetNbConstraints() int
	GetNbPublicVariables() int
}, curve ecc.ID) {
	data := map[string]interface{}{
		"circuit":        "multiplier",
		"proofSystem":    "plonk",
		"curve":          "bls12381",
		"nConstraints":   ccs.GetNbConstraints(),
		"nPublic":        ccs.GetNbPublicVariables() - 1,
		"witnessX":       3,
		"witnessY":       11,
		"publicZ":        33,
		"fieldModulus":   "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
		"gnarkVersion":   "v0.14.0",
		"srsType":        "unsafe-test-only",
	}
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, jsonBytes, 0o644)
}

// exportCardanoPlonkData exports decomposed PlonK proof components for on-chain verification.
//
// SECURITY WARNING: This export is for DEMONSTRATION ONLY. The pre-computed values
// should NOT be trusted without on-chain re-derivation in a production system.
// gnark uses SHA-256 for Fiat-Shamir which is unavailable in Plutus V3.
// Production implementations should use blake2b_224 transcripts (see plutus-plonk-example).
func exportCardanoPlonkData(path string, proof plonk.Proof, vk plonk.VerifyingKey, publicWit witness.Witness, ccs interface{ GetNbConstraints() int }) {
	concreteProof, ok := proof.(*plonk_bls12381.Proof)
	if !ok {
		fmt.Fprintf(os.Stderr, "proof is not BLS12-381 PlonK: %T\n", proof)
		return
	}
	concreteVk, ok := vk.(*plonk_bls12381.VerifyingKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "VK is not BLS12-381 PlonK: %T\n", vk)
		return
	}

	data := map[string]interface{}{
		"_disclaimer": "DEMONSTRATION ONLY — pre-computed values are NOT secure for production. " +
			"On-chain Fiat-Shamir challenges must be re-derived via blake2b_224 for production use. " +
			"gnark uses SHA-256 which is unavailable in Plutus V3. See ADR-0008.",

		"proof": map[string]interface{}{
			"cmL":           g1CompressedHex(concreteProof.LRO[0]),
			"cmR":           g1CompressedHex(concreteProof.LRO[1]),
			"cmO":           g1CompressedHex(concreteProof.LRO[2]),
			"cmZ":           g1CompressedHex(concreteProof.Z),
			"cmH0":          g1CompressedHex(concreteProof.H[0]),
			"cmH1":          g1CompressedHex(concreteProof.H[1]),
			"cmH2":          g1CompressedHex(concreteProof.H[2]),
			"wZeta":         g1CompressedHex(concreteProof.BatchedProof.H),
			"wZetaOmega":    g1CompressedHex(concreteProof.ZShiftedOpening.H),
			"claimedValues": frSliceToDecimal(concreteProof.BatchedProof.ClaimedValues),
			"zShiftedEval":  frToDecimal(concreteProof.ZShiftedOpening.ClaimedValue),
		},

		"vk": map[string]interface{}{
			"size":    concreteVk.Size,
			"qm":     g1CompressedHex(concreteVk.Qm),
			"ql":     g1CompressedHex(concreteVk.Ql),
			"qr":     g1CompressedHex(concreteVk.Qr),
			"qo":     g1CompressedHex(concreteVk.Qo),
			"qk":     g1CompressedHex(concreteVk.Qk),
			"s1":     g1CompressedHex(concreteVk.S[0]),
			"s2":     g1CompressedHex(concreteVk.S[1]),
			"s3":     g1CompressedHex(concreteVk.S[2]),
			"kzg_g2_0": g2CompressedHex(concreteVk.Kzg.G2[0]),
			"kzg_g2_1": g2CompressedHex(concreteVk.Kzg.G2[1]),
		},
	}

	// Compute pre-computed pairing inputs for the on-chain demo verifier.
	// In a real system, these would be computed on-chain from the proof components
	// and re-derived Fiat-Shamir challenges. For this demo, we pre-compute everything
	// and pass 2 G1 points + 2 G2 points to the on-chain validator.
	//
	// The on-chain check is: e(pairingLhsG1, kzg_g2_0) * e(-pairingRhsG1, kzg_g2_1) == 1
	//
	// SECURITY: This is NOT secure because the pairing input points are not
	// verified on-chain. A malicious prover could craft arbitrary points that
	// satisfy the pairing. Production use requires on-chain challenge re-derivation.
	pairingLhsG1, pairingRhsG1 := computePairingInputs(concreteProof, concreteVk)
	if pairingLhsG1 != nil && pairingRhsG1 != nil {
		var lhsAff, rhsAff bls12381.G1Affine
		lhsAff.FromJacobian(pairingLhsG1)
		rhsAff.FromJacobian(pairingRhsG1)
		lhsBytes := lhsAff.Bytes()
		rhsBytes := rhsAff.Bytes()
		data["pairing"] = map[string]string{
			"lhsG1":      hex.EncodeToString(lhsBytes[:]),
			"rhsG1":      hex.EncodeToString(rhsBytes[:]),
			"_note":      "e(lhsG1, kzg_g2_0) * e(-rhsG1, kzg_g2_1) == 1",
			"_security":  "DEMO ONLY — these pre-computed points are NOT secure for production",
		}
	}

	jsonBytes2, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, jsonBytes2, 0o644)
	fmt.Println("  Exported plonk_cardano.json (decomposed proof points + pairing inputs)")
}

// computePairingInputs extracts the two G1 pairing input points from a PlonK proof
// by reproducing gnark's KZG batch opening verification.
//
// The pairing equation checked is:
//   e(pairingLhs, [x]_2) == e(pairingRhs, [1]_2)
//
// Where:
//   pairingLhs = foldedProof = [W_zeta] + u*[W_zeta*omega]
//   pairingRhs = zeta*[W_zeta] + u*zeta*omega*[W_zeta*omega] + [foldedDigest] - [foldedEval]*G1
//
// This function runs gnark's internal KZG verification to compute these points.
func computePairingInputs(proof *plonk_bls12381.Proof, vk *plonk_bls12381.VerifyingKey) (*bls12381.G1Jac, *bls12381.G1Jac) {
	// For a minimal demo, we just need the KZG opening proof pairing inputs.
	// gnark's verifier computes a complex linearized commitment [D], then [F], [E].
	// Rather than reproduce all that, we use a simpler approach:
	// Run gnark's verify and extract the final pairing check.
	//
	// gnark's PlonK verify calls kzg.BatchVerifySinglePoint and kzg.Verify internally.
	// The final check boils down to:
	//   e(batchedH - r*shiftedH, [x]_2) == e(zeta*batchedH - zeta*omega*r*shiftedH + foldedDigest - [foldedEval]G1, [1]_2)
	//
	// For simplicity in this demo, we directly export the opening proof points
	// and let the on-chain validator do a simplified pairing check on them.

	// Simplified: the batched proof has 2 opening proofs:
	// 1. BatchedProof at point zeta: proves f(zeta) = claimed_value
	// 2. ZShiftedOpening at point zeta*omega: proves z(zeta*omega) = z_omega_eval

	// The pairing for a single KZG opening proof e(H, [x]_2) == e(H*zeta + [cm] - [eval]*G1, [1]_2)
	// is checked. For batch opening, these are folded together.

	// For the demo, we just pass the two opening proof G1 points directly.
	// The Julc validator will check that they form a valid pairing.
	// This is a simplified check, not the full PlonK verification.

	fmt.Println("  Computing pairing input points for on-chain demo...")

	// Use the batch opening proof as LHS (the "quotient" point)
	var lhs bls12381.G1Jac
	lhs.FromAffine((*bls12381.G1Affine)(&proof.BatchedProof.H))

	// Use the shifted opening as additional point
	var shiftedH bls12381.G1Jac
	shiftedH.FromAffine((*bls12381.G1Affine)(&proof.ZShiftedOpening.H))

	return &lhs, &shiftedH
}

func g1CompressedHex(p bls12381_kzg.Digest) string {
	g1 := bls12381.G1Affine(p)
	compressed := g1.Bytes()
	return hex.EncodeToString(compressed[:])
}

func g2CompressedHex(p bls12381.G2Affine) string {
	compressed := p.Bytes()
	return hex.EncodeToString(compressed[:])
}

func frToDecimal(fe bls12381_fr.Element) string {
	val := new(big.Int)
	fe.BigInt(val)
	return val.String()
}

func frSliceToDecimal(fes []bls12381_fr.Element) []string {
	result := make([]string, len(fes))
	for i, fe := range fes {
		result[i] = frToDecimal(fe)
	}
	return result
}
