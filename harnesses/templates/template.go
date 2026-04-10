// Crucible ML-KEM Harness Template — Go
//
// Wire your ML-KEM implementation to Crucible's test battery.
// Reference: FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism
//            (https://doi.org/10.6028/NIST.FIPS.203)
//
// Build: go build -o harness-yourname .
// Run:   crucible ./harness-yourname --battery ml-kem
//
// ## Architecture
//
// The battery tests functions at two levels:
//
// Low-level (auxiliary algorithms, FIPS 203 §4):
//   Compress_d, Decompress_d, ByteEncode_d, ByteDecode_d,
//   NTT, NTT_inv, MultiplyNTTs, SamplePolyCBD, SampleNTT
//
// High-level (internal algorithms, FIPS 203 §6):
//   ML_KEM_KeyGen (Alg 16), ML_KEM_Encaps (Alg 17), ML_KEM_Decaps (Alg 18)
//
// These are the INTERNAL algorithms (§6), not the external ones (§7).
// All randomness is provided as explicit input by the battery.
//
// You do NOT need to implement every function. List only those your
// harness supports in the handshake; Crucible skips unsupported tests.
//
// Key/ciphertext sizes (FIPS 203, Table 3):
//   ML-KEM-512:  ek=800   dk=1632  ct=768   ss=32
//   ML-KEM-768:  ek=1184  dk=2400  ct=1088  ss=32
//   ML-KEM-1024: ek=1568  dk=3168  ct=1568  ss=32
//
// Constants: n=256, q=3329, ζ=17.

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type Request struct {
	Function string            `json:"function"`
	Inputs   map[string]string `json:"inputs"`
	Params   map[string]int64  `json:"params"`
}

type Response struct {
	Outputs     map[string]string `json:"outputs,omitempty"`
	Error       *string           `json:"error,omitempty"`
	Unsupported bool              `json:"unsupported,omitempty"`
}

type Handshake struct {
	Implementation string   `json:"implementation"`
	Functions      []string `json:"functions"`
}

func main() {
	enc := json.NewEncoder(os.Stdout)

	// TODO: Update implementation name and supported functions list.
	enc.Encode(Handshake{
		Implementation: "your-implementation-name",
		Functions: []string{
			// List only functions your harness implements.
			"Compress_d",
			"Decompress_d",
			"ByteEncode_d",
			"ByteDecode_d",
			"NTT",
			"NTT_inv",
			"MultiplyNTTs",
			"SamplePolyCBD",
			"SampleNTT",
			"ML_KEM_KeyGen",
			"ML_KEM_Encaps",
			"ML_KEM_Decaps",
		},
	})

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errMsg := fmt.Sprintf("invalid JSON: %v", err)
			enc.Encode(Response{Error: &errMsg})
			continue
		}
		enc.Encode(handle(&req))
	}
}

func handle(req *Request) Response {
	switch req.Function {
	case "Compress_d":
		return handleCompressD(req)
	case "Decompress_d":
		return handleDecompressD(req)
	case "ByteEncode_d":
		return handleByteEncodeD(req)
	case "ByteDecode_d":
		return handleByteDecodeD(req)
	case "NTT":
		return handleNTT(req)
	case "NTT_inv":
		return handleNTTInv(req)
	case "MultiplyNTTs":
		return handleMultiplyNTTs(req)
	case "SamplePolyCBD":
		return handleSamplePolyCBD(req)
	case "SampleNTT":
		return handleSampleNTT(req)
	case "ML_KEM_KeyGen":
		return handleKeyGen(req)
	case "ML_KEM_Encaps":
		return handleEncaps(req)
	case "ML_KEM_Decaps":
		return handleDecaps(req)
	default:
		return Response{Unsupported: true}
	}
}

// ---- Helpers ----

func getBytes(req *Request, key string) ([]byte, error) {
	h, ok := req.Inputs[key]
	if !ok {
		return nil, fmt.Errorf("missing input '%s'", key)
	}
	return hex.DecodeString(h)
}

func getParam(req *Request, key string) (int64, bool) {
	v, ok := req.Params[key]
	return v, ok
}

func errResp(msg string) Response {
	return Response{Error: &msg}
}

func okResp(outputs map[string]string) Response {
	return Response{Outputs: outputs}
}

// ---- Low-level auxiliary functions ----
// Polynomials: 512 bytes = 256 coefficients × 2 bytes little-endian.

func handleCompressD(req *Request) Response {
	// FIPS 203 §4.2.1, Eq 4.7: x → ⌈(2^d / q) · x⌋ mod 2^d
	// Input "x": 2 bytes LE. Param "d": 1–11. Output "y": 2 bytes LE.
	d, _ := getParam(req, "d")
	xBytes, err := getBytes(req, "x")
	if err != nil {
		return errResp(err.Error())
	}
	x := uint32(binary.LittleEndian.Uint16(pad2(xBytes)))

	// TODO: Call your Compress_d(x, d). Must use integer arithmetic (§3.3).
	_ = d
	_ = x
	panic("TODO: implement Compress_d")
}

func handleDecompressD(req *Request) Response {
	// FIPS 203 §4.2.1, Eq 4.8: y → ⌈(q / 2^d) · y⌋
	// Input "y": 2 bytes LE. Param "d": 1–11. Output "x": 2 bytes LE.
	d, _ := getParam(req, "d")
	yBytes, err := getBytes(req, "y")
	if err != nil {
		return errResp(err.Error())
	}
	y := uint32(binary.LittleEndian.Uint16(pad2(yBytes)))

	// TODO: Call your Decompress_d(y, d).
	_ = d
	_ = y
	panic("TODO: implement Decompress_d")
}

func handleByteEncodeD(req *Request) Response {
	// FIPS 203, Algorithm 5. Input "F": 512 bytes. Param "d": 1–12.
	// Output "B": 32·d bytes.
	panic("TODO: implement ByteEncode_d")
}

func handleByteDecodeD(req *Request) Response {
	// FIPS 203, Algorithm 6. Input "B": 32·d bytes. Param "d": 1–12.
	// Output "F": 512 bytes. For d=12: coefficients reduced mod q.
	panic("TODO: implement ByteDecode_d")
}

func handleNTT(req *Request) Response {
	// FIPS 203, Algorithm 9. Input "f": 512 bytes. Output "f_hat": 512 bytes.
	// Must use ζ=17 with BitRev_7 ordering (not Montgomery domain).
	panic("TODO: implement NTT")
}

func handleNTTInv(req *Request) Response {
	// FIPS 203, Algorithm 10. Input "f_hat": 512 bytes. Output "f": 512 bytes.
	// Final multiplication by 128^{-1} = 3303 mod q is required.
	panic("TODO: implement NTT_inv")
}

func handleMultiplyNTTs(req *Request) Response {
	// FIPS 203, Algorithm 11. Input "f_hat", "g_hat": 512 bytes each.
	// Output "h_hat": 512 bytes. Uses BaseCaseMultiply (Alg 12).
	panic("TODO: implement MultiplyNTTs")
}

func handleSamplePolyCBD(req *Request) Response {
	// FIPS 203, Algorithm 8. Input "B": 64·η bytes. Param "eta": 2 or 3.
	// Output "f": 512 bytes. Coefficients in [-η, η] (mod q).
	panic("TODO: implement SamplePolyCBD")
}

func handleSampleNTT(req *Request) Response {
	// FIPS 203, Algorithm 7. Input "B": 34 bytes (ρ + 2 index bytes).
	// Output "a_hat": 512 bytes. All coefficients < q (rejection sampling).
	panic("TODO: implement SampleNTT")
}

// ---- High-level internal algorithms ----

func handleKeyGen(req *Request) Response {
	// FIPS 203 §6.1, Algorithm 16: ML-KEM.KeyGen_internal(d, z)
	// Input "randomness": 64 bytes (d||z). Param "param_set": 512/768/1024.
	// Output "ek" (encapsulation key), "dk" (decapsulation key).
	// dk = dk_PKE || ek || H(ek) || z. Must be deterministic.
	panic("TODO: implement ML_KEM_KeyGen")
}

func handleEncaps(req *Request) Response {
	// FIPS 203 §6.2, Algorithm 17: ML-KEM.Encaps_internal(ek, m)
	// Input "ek": encapsulation key, "randomness": 32 bytes (message m).
	// Output "c": ciphertext, "K": 32-byte shared secret.
	// Validate ek first (§7.2): ByteEncode_12(ByteDecode_12(ek)) == ek.
	panic("TODO: implement ML_KEM_Encaps")
}

func handleDecaps(req *Request) Response {
	// FIPS 203 §6.3, Algorithm 18: ML-KEM.Decaps_internal(dk, c)
	// Input "c": ciphertext, "dk": decapsulation key.
	// Output "K": 32-byte shared secret (or implicit rejection value).
	// MUST always return a 32-byte K — never error on invalid ciphertexts.
	// Comparison of re-encrypted ciphertext MUST be constant-time.
	panic("TODO: implement ML_KEM_Decaps")
}

func pad2(b []byte) []byte {
	if len(b) >= 2 {
		return b[:2]
	}
	var buf [2]byte
	copy(buf[:], b)
	return buf[:]
}
