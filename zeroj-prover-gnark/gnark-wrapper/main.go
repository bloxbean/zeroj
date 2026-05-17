package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func init() {
	// Limit Go scheduler parallelism when running as a shared library inside
	// a JVM via FFM. The Go runtime's work-stealing scheduler can crash
	// (index out of range in runtime.stealWork / pMask.read) when it races
	// with JVM thread management. Setting GOMAXPROCS to 2 reduces the
	// scheduler pressure while still allowing goroutines to make progress.
	// For full reliability, also set GOMAXPROCS=2 as an env var before
	// loading the library (the Go runtime reads it at bootstrap time).
	runtime.GOMAXPROCS(2)
}

const (
	PROVER_OK    = 0
	PROVER_ERROR = 1
)

type ProveResult struct {
	ProofJSON  string `json:"proof"`
	PublicJSON string `json:"public"`
	ProvingMs  int64  `json:"provingMs"`
}

func parseCurve(curveName string) (ecc.ID, error) {
	switch strings.ToLower(curveName) {
	case "bls12381", "bls12-381":
		return ecc.BLS12_381, nil
	case "bn254", "bn128", "alt_bn128":
		return ecc.BN254, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %s", curveName)
	}
}

func curveWireName(curve ecc.ID) string {
	switch curve {
	case ecc.BLS12_381:
		return "bls12381"
	case ecc.BN254:
		return "bn128"
	default:
		return curve.String()
	}
}

// ============================================================
// Groth16
// ============================================================

//export zeroj_groth16_prove
func zeroj_groth16_prove(
	curveCStr *C.char, r1csPath *C.char, pkPath *C.char, witnessPath *C.char,
	proofOut **C.char, publicOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	cs := groth16.NewCS(curve)
	if err := readFromFile(C.GoString(r1csPath), cs); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
		return PROVER_ERROR
	}

	pk := groth16.NewProvingKey(curve)
	if err := readFromFile(C.GoString(pkPath), pk); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read proving key: %v", err))
		return PROVER_ERROR
	}

	wit, err := readWitness(C.GoString(witnessPath), curve)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	start := time.Now()
	proof, err := groth16.Prove(cs, pk, wit)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("proving failed: %v", err))
		return PROVER_ERROR
	}

	return writeProveResult(proof, wit, curve, time.Since(start).Milliseconds(), "groth16", proofOut, publicOut, errorOut)
}

//export zeroj_groth16_setup
func zeroj_groth16_setup(
	curveCStr *C.char, r1csPath *C.char,
	pkPathOut **C.char, vkOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	cs := groth16.NewCS(curve)
	if err := readFromFile(C.GoString(r1csPath), cs); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
		return PROVER_ERROR
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("setup failed: %v", err))
		return PROVER_ERROR
	}

	return writeSetupResult(pk, vk, curve, "groth16", "zeroj-groth16-pk-*.bin", pkPathOut, vkOut, errorOut)
}

// ============================================================
// PlonK
// ============================================================

//export zeroj_plonk_setup
func zeroj_plonk_setup(
	curveCStr *C.char, r1csPath *C.char,
	pkPathOut **C.char, vkOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	cs := plonk.NewCS(curve)
	if err := readFromFile(C.GoString(r1csPath), cs); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read SparseR1CS: %v", err))
		return PROVER_ERROR
	}

	// Generate KZG SRS (unsafe — for testing/dev only)
	srs, srsLagrange, err := unsafekzg.NewSRS(cs)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to generate SRS: %v", err))
		return PROVER_ERROR
	}

	pk, vk, err := plonk.Setup(cs, srs, srsLagrange)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("plonk setup failed: %v", err))
		return PROVER_ERROR
	}

	return writeSetupResult(pk, vk, curve, "plonk", "zeroj-plonk-pk-*.bin", pkPathOut, vkOut, errorOut)
}

//export zeroj_plonk_prove
func zeroj_plonk_prove(
	curveCStr *C.char, r1csPath *C.char, pkPath *C.char, witnessPath *C.char,
	proofOut **C.char, publicOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	cs := plonk.NewCS(curve)
	if err := readFromFile(C.GoString(r1csPath), cs); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read SparseR1CS: %v", err))
		return PROVER_ERROR
	}

	pk := plonk.NewProvingKey(curve)
	if err := readFromFile(C.GoString(pkPath), pk); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read plonk proving key: %v", err))
		return PROVER_ERROR
	}

	wit, err := readWitness(C.GoString(witnessPath), curve)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	start := time.Now()
	proof, err := plonk.Prove(cs, pk, wit)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("plonk proving failed: %v", err))
		return PROVER_ERROR
	}

	return writeProveResult(proof, wit, curve, time.Since(start).Milliseconds(), "plonk", proofOut, publicOut, errorOut)
}

//export zeroj_plonk_verify
func zeroj_plonk_verify(
	curveCStr *C.char, vkPath *C.char, proofBase64 *C.char, witnessPath *C.char,
	errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	vk := plonk.NewVerifyingKey(curve)
	if err := readFromFile(C.GoString(vkPath), vk); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read plonk vk: %v", err))
		return PROVER_ERROR
	}

	proofBytes, err := base64.StdEncoding.DecodeString(C.GoString(proofBase64))
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to decode proof: %v", err))
		return PROVER_ERROR
	}

	proof := plonk.NewProof(curve)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to deserialize plonk proof: %v", err))
		return PROVER_ERROR
	}

	wit, err := readWitness(C.GoString(witnessPath), curve)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	publicWit, err := wit.Public()
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to extract public witness: %v", err))
		return PROVER_ERROR
	}

	if err := plonk.Verify(proof, vk, publicWit); err != nil {
		*errorOut = C.CString(fmt.Sprintf("plonk verification failed: %v", err))
		return PROVER_ERROR
	}

	return PROVER_OK
}

// ============================================================
// Common exports
// ============================================================

//export zeroj_gnark_version
func zeroj_gnark_version() *C.char {
	return C.CString("v0.14.0")
}

//export zeroj_free
func zeroj_free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

// ============================================================
// Helpers — use io.ReaderFrom/io.WriterTo interfaces
// ============================================================

type readerFrom interface {
	ReadFrom(r io.Reader) (int64, error)
}

type writerTo interface {
	WriteTo(w io.Writer) (int64, error)
}

func readFromFile(path string, target readerFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()
	if _, err := target.ReadFrom(file); err != nil {
		return fmt.Errorf("failed to read %s: %v", path, err)
	}
	return nil
}

func readWitness(path string, curve ecc.ID) (witness.Witness, error) {
	wit, err := witness.New(curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open witness: %v", err)
	}
	defer file.Close()
	if _, err := wit.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("failed to read witness: %v", err)
	}
	return wit, nil
}

func serializeTo(obj writerTo, protocol string, curve ecc.ID) (string, error) {
	var buf bytes.Buffer
	if _, err := obj.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to serialize: %v", err)
	}
	result := map[string]interface{}{
		"binary":   base64.StdEncoding.EncodeToString(buf.Bytes()),
		"protocol": protocol,
		"curve":    curveWireName(curve),
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func writeProveResult(proof writerTo, wit witness.Witness, curve ecc.ID, provingMs int64, protocol string,
	proofOut **C.char, publicOut **C.char, errorOut **C.char) C.int {

	proofJSON, err := serializeTo(proof, protocol, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize proof: %v", err))
		return PROVER_ERROR
	}

	publicJSON, err := serializePublicWitness(wit, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize public witness: %v", err))
		return PROVER_ERROR
	}

	result := ProveResult{ProofJSON: proofJSON, PublicJSON: publicJSON, ProvingMs: provingMs}
	resultBytes, _ := json.Marshal(result)
	*proofOut = C.CString(string(resultBytes))
	*publicOut = C.CString(publicJSON)
	return PROVER_OK
}

func writeSetupResult(pk writerTo, vk writerTo, curve ecc.ID, protocol string, pkPattern string,
	pkPathOut **C.char, vkOut **C.char, errorOut **C.char) C.int {

	tmpFile, err := os.CreateTemp("", pkPattern)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to create temp file: %v", err))
		return PROVER_ERROR
	}
	if _, err := pk.WriteTo(tmpFile); err != nil {
		tmpFile.Close()
		*errorOut = C.CString(fmt.Sprintf("failed to write pk: %v", err))
		return PROVER_ERROR
	}
	tmpFile.Close()

	vkJSON, err := serializeTo(vk, protocol, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize vk: %v", err))
		return PROVER_ERROR
	}

	*pkPathOut = C.CString(tmpFile.Name())
	*vkOut = C.CString(vkJSON)
	return PROVER_OK
}

func serializePublicWitness(wit witness.Witness, curve ecc.ID) (string, error) {
	publicWit, err := wit.Public()
	if err != nil {
		return "", fmt.Errorf("failed to extract public witness: %v", err)
	}
	data, err := publicWit.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public witness: %v", err)
	}
	fieldSize := getFieldSize(curve)
	if len(data) < 12 {
		return "[]", nil
	}
	nbPublic := int(binary.BigEndian.Uint32(data[8:12]))
	elemData := data[12:]
	var values []string
	for i := 0; i < nbPublic && (i+1)*fieldSize <= len(elemData); i++ {
		offset := i * fieldSize
		val := new(big.Int).SetBytes(elemData[offset : offset+fieldSize])
		values = append(values, val.String())
	}
	jsonBytes, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// getFieldSize returns the byte size of a scalar field element (Fr) for the given curve.
// gnark witness serialization uses Fr elements, NOT base field (Fq) elements.
// BN254 Fr: 254 bits → 32 bytes. BLS12-381 Fr: 255 bits → 32 bytes.
func getFieldSize(curve ecc.ID) int {
	switch curve {
	case ecc.BN254:
		return 32
	case ecc.BLS12_381:
		return 32
	default:
		return 32
	}
}

// ============================================================
// Generic R1CS circuit — replays constraints via gnark frontend
// ============================================================

// R1CS constraint input from Java: each linear combination is a map of wireIdx→coefficient
type R1CSConstraintJSON struct {
	A map[string]string `json:"a"`
	B map[string]string `json:"b"`
	C map[string]string `json:"c"`
}

// Full R1CS input from Java
type R1CSInput struct {
	NumPublic   int                  `json:"numPublic"`
	NumWires    int                  `json:"numWires"`
	Constraints []R1CSConstraintJSON `json:"constraints"`
}

// Witness values input from Java (wire values excluding wire 0)
type WitnessInput struct {
	NumPublic int      `json:"numPublic"`
	Values    []string `json:"values"` // values for wires 1..numWires-1
}

// GenericR1CS is a gnark circuit that replays R1CS constraints.
// Public/Secret slices match the iden3 wire layout (excluding wire 0).
type GenericR1CS struct {
	Public []frontend.Variable `gnark:",public"`
	Secret []frontend.Variable
	data   *R1CSInput // constraint data, used during Define() only
}

func (c *GenericR1CS) Define(api frontend.API) error {
	numPublic := len(c.Public)

	// Wire mapping: wire 0 = constant 1, wires 1..numPublic = Public, rest = Secret
	wires := make([]frontend.Variable, c.data.NumWires)
	wires[0] = frontend.Variable(1)
	for i := 0; i < numPublic; i++ {
		wires[i+1] = c.Public[i]
	}
	for i := 0; i < len(c.Secret); i++ {
		wires[numPublic+1+i] = c.Secret[i]
	}

	for _, con := range c.data.Constraints {
		a := buildLC(api, wires, con.A)
		b := buildLC(api, wires, con.B)
		cc := buildLC(api, wires, con.C)
		api.AssertIsEqual(api.Mul(a, b), cc)
	}
	return nil
}

func buildLC(api frontend.API, wires []frontend.Variable, terms map[string]string) frontend.Variable {
	if len(terms) == 0 {
		return frontend.Variable(0)
	}
	var result frontend.Variable
	first := true
	for wireIdxStr, coeffStr := range terms {
		wireIdx, _ := strconv.Atoi(wireIdxStr)
		coeff, _ := new(big.Int).SetString(coeffStr, 10)
		term := api.Mul(wires[wireIdx], coeff)
		if first {
			result = term
			first = false
		} else {
			result = api.Add(result, term)
		}
	}
	return result
}

// compileAndProveGroth16 compiles the circuit via gnark's frontend, then runs setup + prove.
func compileAndProveGroth16(curve ecc.ID, r1csData *R1CSInput, witnessData *WitnessInput) (
	proof groth16.Proof, vk groth16.VerifyingKey, wit witness.Witness, provingMs int64, err error) {

	numPublic := r1csData.NumPublic
	numSecret := r1csData.NumWires - numPublic - 1

	// 1. Compile circuit
	circuit := &GenericR1CS{
		Public: make([]frontend.Variable, numPublic),
		Secret: make([]frontend.Variable, numSecret),
		data:   r1csData,
	}
	cs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("compilation failed: %v", err)
	}

	// 2. Build witness assignment
	assignment := &GenericR1CS{
		Public: make([]frontend.Variable, numPublic),
		Secret: make([]frontend.Variable, numSecret),
	}
	for i := 0; i < numPublic; i++ {
		val, ok := new(big.Int).SetString(witnessData.Values[i], 10)
		if !ok {
			return nil, nil, nil, 0, fmt.Errorf("invalid public witness value at %d", i)
		}
		assignment.Public[i] = val
	}
	for i := 0; i < numSecret; i++ {
		val, ok := new(big.Int).SetString(witnessData.Values[numPublic+i], 10)
		if !ok {
			return nil, nil, nil, 0, fmt.Errorf("invalid secret witness value at %d", i)
		}
		assignment.Secret[i] = val
	}

	wit, err = frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to build witness: %v", err)
	}

	// 3. Setup
	var pk groth16.ProvingKey
	pk, vk, err = groth16.Setup(cs)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("setup failed: %v", err)
	}

	// 4. Prove
	start := time.Now()
	proof, err = groth16.Prove(cs, pk, wit)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("proving failed: %v", err)
	}
	provingMs = time.Since(start).Milliseconds()
	return
}

// compileAndProvePlonk compiles the circuit via gnark's frontend for PlonK, then runs setup + prove.
func compileAndProvePlonk(curve ecc.ID, r1csData *R1CSInput, witnessData *WitnessInput) (
	proof plonk.Proof, vk plonk.VerifyingKey, wit witness.Witness, provingMs int64, err error) {

	numPublic := r1csData.NumPublic
	numSecret := r1csData.NumWires - numPublic - 1

	// 1. Compile circuit (PlonK uses SparseR1CS builder)
	circuit := &GenericR1CS{
		Public: make([]frontend.Variable, numPublic),
		Secret: make([]frontend.Variable, numSecret),
		data:   r1csData,
	}
	cs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("plonk compilation failed: %v", err)
	}

	// 2. Build witness assignment
	assignment := &GenericR1CS{
		Public: make([]frontend.Variable, numPublic),
		Secret: make([]frontend.Variable, numSecret),
	}
	for i := 0; i < numPublic; i++ {
		val, ok := new(big.Int).SetString(witnessData.Values[i], 10)
		if !ok {
			return nil, nil, nil, 0, fmt.Errorf("invalid public witness value at %d", i)
		}
		assignment.Public[i] = val
	}
	for i := 0; i < numSecret; i++ {
		val, ok := new(big.Int).SetString(witnessData.Values[numPublic+i], 10)
		if !ok {
			return nil, nil, nil, 0, fmt.Errorf("invalid secret witness value at %d", i)
		}
		assignment.Secret[i] = val
	}

	wit, err = frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to build witness: %v", err)
	}

	// 3. Generate SRS + Setup
	srsInst, srsLagrange, err := unsafekzg.NewSRS(cs)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to generate SRS: %v", err)
	}

	var pk plonk.ProvingKey
	pk, vk, err = plonk.Setup(cs, srsInst, srsLagrange)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("plonk setup failed: %v", err)
	}

	// 4. Prove
	start := time.Now()
	proof, err = plonk.Prove(cs, pk, wit)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("plonk proving failed: %v", err)
	}
	provingMs = time.Since(start).Milliseconds()
	return
}

// ============================================================
// Groth16 full prove: JSON constraints + JSON witness → proof
// ============================================================

//export zeroj_groth16_fullprove
func zeroj_groth16_fullprove(
	curveCStr *C.char, constraintsJsonC *C.char, valuesJsonC *C.char,
	proofOut **C.char, publicOut **C.char, vkOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	var r1csData R1CSInput
	if err := json.Unmarshal([]byte(C.GoString(constraintsJsonC)), &r1csData); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to parse constraints JSON: %v", err))
		return PROVER_ERROR
	}

	var witnessData WitnessInput
	if err := json.Unmarshal([]byte(C.GoString(valuesJsonC)), &witnessData); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to parse witness JSON: %v", err))
		return PROVER_ERROR
	}

	proof, vk, wit, provingMs, err := compileAndProveGroth16(curve, &r1csData, &witnessData)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	return writeFullProveResult(proof, vk, wit, curve, provingMs, "groth16", proofOut, publicOut, vkOut, errorOut)
}

// ============================================================
// PlonK full prove: JSON constraints + JSON witness → proof
// ============================================================

//export zeroj_plonk_fullprove
func zeroj_plonk_fullprove(
	curveCStr *C.char, constraintsJsonC *C.char, valuesJsonC *C.char,
	proofOut **C.char, publicOut **C.char, vkOut **C.char, errorOut **C.char,
) C.int {
	curve, err := parseCurve(C.GoString(curveCStr))
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	var r1csData R1CSInput
	if err := json.Unmarshal([]byte(C.GoString(constraintsJsonC)), &r1csData); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to parse constraints JSON: %v", err))
		return PROVER_ERROR
	}

	var witnessData WitnessInput
	if err := json.Unmarshal([]byte(C.GoString(valuesJsonC)), &witnessData); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to parse witness JSON: %v", err))
		return PROVER_ERROR
	}

	proof, vk, wit, provingMs, err := compileAndProvePlonk(curve, &r1csData, &witnessData)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	return writeFullProveResult(proof, vk, wit, curve, provingMs, "plonk", proofOut, publicOut, vkOut, errorOut)
}

func writeFullProveResult(proof writerTo, vk writerTo, wit witness.Witness, curve ecc.ID,
	provingMs int64, protocol string,
	proofOut **C.char, publicOut **C.char, vkOut **C.char, errorOut **C.char) C.int {

	proofJSON, err := serializeTo(proof, protocol, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize proof: %v", err))
		return PROVER_ERROR
	}

	publicJSON, err := serializePublicWitness(wit, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize public witness: %v", err))
		return PROVER_ERROR
	}

	vkJSON, err := serializeTo(vk, protocol, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize vk: %v", err))
		return PROVER_ERROR
	}

	result := ProveResult{ProofJSON: proofJSON, PublicJSON: publicJSON, ProvingMs: provingMs}
	resultBytes, _ := json.Marshal(result)
	*proofOut = C.CString(string(resultBytes))
	*publicOut = C.CString(publicJSON)
	*vkOut = C.CString(vkJSON)
	return PROVER_OK
}

func main() {}
