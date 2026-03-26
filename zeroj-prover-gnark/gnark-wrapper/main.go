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
	"math/big"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// Error codes matching rapidsnark convention
const (
	PROVER_OK    = 0
	PROVER_ERROR = 1
)

// ProveResult holds the JSON-encoded proof and public witness
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

//export zeroj_groth16_prove
func zeroj_groth16_prove(
	curveCStr *C.char,
	r1csPath *C.char,
	pkPath *C.char,
	witnessPath *C.char,
	proofOut **C.char,
	publicOut **C.char,
	errorOut **C.char,
) C.int {
	curveStr := C.GoString(curveCStr)
	curve, err := parseCurve(curveStr)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	// Read R1CS
	r1csFile, err := os.Open(C.GoString(r1csPath))
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to open r1cs: %v", err))
		return PROVER_ERROR
	}
	defer r1csFile.Close()

	cs := groth16.NewCS(curve)
	if _, err := cs.ReadFrom(r1csFile); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
		return PROVER_ERROR
	}

	// Read proving key
	pkFile, err := os.Open(C.GoString(pkPath))
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to open proving key: %v", err))
		return PROVER_ERROR
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(curve)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read proving key: %v", err))
		return PROVER_ERROR
	}

	// Read witness from file (gnark binary format)
	witnessPathStr := C.GoString(witnessPath)
	wit, err := witness.New(curve.ScalarField())
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to create witness: %v", err))
		return PROVER_ERROR
	}

	witFile, err := os.Open(witnessPathStr)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to open witness file: %v", err))
		return PROVER_ERROR
	}
	defer witFile.Close()

	if _, err := wit.ReadFrom(witFile); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read witness: %v", err))
		return PROVER_ERROR
	}

	// Prove
	start := time.Now()
	proof, err := groth16.Prove(cs, pk, wit)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("proving failed: %v", err))
		return PROVER_ERROR
	}
	provingMs := time.Since(start).Milliseconds()

	// Serialize proof
	proofJSON, err := serializeProof(proof)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize proof: %v", err))
		return PROVER_ERROR
	}

	// Extract and serialize public witness
	publicWit, err := wit.Public()
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to extract public witness: %v", err))
		return PROVER_ERROR
	}

	publicJSON, err := serializePublicWitness(publicWit, curve)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize public witness: %v", err))
		return PROVER_ERROR
	}

	// Wrap in result with proving time
	result := ProveResult{
		ProofJSON:  proofJSON,
		PublicJSON: publicJSON,
		ProvingMs:  provingMs,
	}
	resultBytes, _ := json.Marshal(result)

	*proofOut = C.CString(string(resultBytes))
	*publicOut = C.CString(publicJSON)

	return PROVER_OK
}

//export zeroj_groth16_setup
func zeroj_groth16_setup(
	curveCStr *C.char,
	r1csPath *C.char,
	pkPathOut **C.char,
	vkOut **C.char,
	errorOut **C.char,
) C.int {
	curveStr := C.GoString(curveCStr)
	curve, err := parseCurve(curveStr)
	if err != nil {
		*errorOut = C.CString(err.Error())
		return PROVER_ERROR
	}

	// Read R1CS
	r1csFile, err := os.Open(C.GoString(r1csPath))
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to open r1cs: %v", err))
		return PROVER_ERROR
	}
	defer r1csFile.Close()

	cs := groth16.NewCS(curve)
	if _, err := cs.ReadFrom(r1csFile); err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to read r1cs: %v", err))
		return PROVER_ERROR
	}

	// Run setup
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("setup failed: %v", err))
		return PROVER_ERROR
	}

	// Write proving key to temp file
	pkTmpFile, err := os.CreateTemp("", "zeroj-pk-*.bin")
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to create pk temp file: %v", err))
		return PROVER_ERROR
	}
	if _, err := pk.WriteTo(pkTmpFile); err != nil {
		pkTmpFile.Close()
		*errorOut = C.CString(fmt.Sprintf("failed to write pk: %v", err))
		return PROVER_ERROR
	}
	pkTmpFile.Close()

	// Serialize VK
	vkJSON, err := serializeVk(vk)
	if err != nil {
		*errorOut = C.CString(fmt.Sprintf("failed to serialize vk: %v", err))
		return PROVER_ERROR
	}

	*pkPathOut = C.CString(pkTmpFile.Name())
	*vkOut = C.CString(vkJSON)

	return PROVER_OK
}

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

// serializeProof converts a gnark proof to a base64-encoded JSON object for transport.
func serializeProof(proof groth16.Proof) (string, error) {
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to write proof: %v", err)
	}
	result := map[string]interface{}{
		"proofBinary": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"protocol":    "groth16",
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// serializePublicWitness extracts public signals as a JSON array of decimal strings.
func serializePublicWitness(wit witness.Witness, curve ecc.ID) (string, error) {
	// Marshal to binary and extract field elements
	data, err := wit.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public witness: %v", err)
	}

	// gnark binary witness format: [nbPublic uint32][nbSecret uint32][elements...]
	// For public witness, nbSecret = 0
	// Each element is a big-endian field element (32 bytes for BN254, 48 for BLS12-381)
	fieldSize := getFieldSize(curve)
	if len(data) < 8 {
		return "[]", nil
	}

	// Skip the 8-byte header (nbPublic + nbSecret as uint32 LE)
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

// serializeVk converts a gnark verification key to a base64-encoded JSON object.
func serializeVk(vk groth16.VerifyingKey) (string, error) {
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("failed to write vk: %v", err)
	}
	result := map[string]interface{}{
		"vkBinary": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"protocol": "groth16",
	}
	jsonBytes, err := json.Marshal(result)
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

// Dummy main required for cgo shared library
func main() {}
