package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
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

	return writeSetupResult(pk, vk, "groth16", "zeroj-groth16-pk-*.bin", pkPathOut, vkOut, errorOut)
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

	return writeSetupResult(pk, vk, "plonk", "zeroj-plonk-pk-*.bin", pkPathOut, vkOut, errorOut)
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

func serializeTo(obj writerTo, protocol string) (string, error) {
	var buf bytes.Buffer
	if _, err := obj.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to serialize: %v", err)
	}
	result := map[string]interface{}{
		"binary":   base64.StdEncoding.EncodeToString(buf.Bytes()),
		"protocol": protocol,
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func writeProveResult(proof writerTo, wit witness.Witness, curve ecc.ID, provingMs int64, protocol string,
	proofOut **C.char, publicOut **C.char, errorOut **C.char) C.int {

	proofJSON, err := serializeTo(proof, protocol)
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

func writeSetupResult(pk writerTo, vk writerTo, protocol string, pkPattern string,
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

	vkJSON, err := serializeTo(vk, protocol)
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
	if len(data) < 8 {
		return "[]", nil
	}
	elemData := data[8:]
	var values []string
	for i := 0; i+fieldSize <= len(elemData); i += fieldSize {
		val := new(big.Int).SetBytes(elemData[i : i+fieldSize])
		values = append(values, val.String())
	}
	jsonBytes, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func getFieldSize(curve ecc.ID) int {
	switch curve {
	case ecc.BN254:
		return 32
	case ecc.BLS12_381:
		return 48
	default:
		return 32
	}
}

func main() {}
