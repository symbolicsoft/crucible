// Crucible ML-DSA Harness Template — Go
//
// Wire your ML-DSA implementation to Crucible's test battery.
// Reference: FIPS 204, Module-Lattice-Based Digital Signature Standard
//            (https://doi.org/10.6028/NIST.FIPS.204)
//
// Build: go build -o harness-yourname .
// Run:   crucible ./harness-yourname --battery ml-dsa
//
// ## Architecture
//
// This harness targets the INTERNAL algorithms from FIPS 204 §6:
//   - ML_DSA_KeyGen  → Algorithm 6  (ML-DSA.KeyGen_internal)
//   - ML_DSA_Sign    → Algorithm 7  (ML-DSA.Sign_internal)
//   - ML_DSA_Verify  → Algorithm 8  (ML-DSA.Verify_internal)
//
// NOT the external algorithms (§5, Algorithms 1–3), which add randomness
// generation and domain-separated message encoding (M' construction).
//
// The "message" input sent by Crucible is the pre-formatted message
// representative M' (a byte string passed directly to Sign_internal /
// Verify_internal). It is NOT the raw application message M.
//
// If your library only exposes the external API (with a context string),
// you can bridge to it: for "pure" ML-DSA with an empty context, the
// external Sign/Verify prepend a 2-byte header (0x00 || 0x00) to M before
// passing it to the internal function as M'. So you would need to strip
// that 2-byte prefix from the "message" input to recover the raw M, then
// call your external API with ctx = "" (the empty string). However, it is
// preferable to call the internal API directly when possible.

package main

import (
	"bufio"
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

	// TODO: Update implementation name.
	enc.Encode(Handshake{
		Implementation: "your-implementation-name",
		Functions: []string{
			"ML_DSA_KeyGen",
			"ML_DSA_Sign",
			"ML_DSA_Verify",
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
	case "ML_DSA_KeyGen":
		return handleKeyGen(req)
	case "ML_DSA_Sign":
		return handleSign(req)
	case "ML_DSA_Verify":
		return handleVerify(req)
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

// ---- Function handlers ----
//
// Key/signature byte sizes per parameter set (FIPS 204, Table 2):
//
//   Parameter set   pk bytes   sk bytes   sig bytes
//   ML-DSA-44       1312       2560       2420
//   ML-DSA-65       1952       4032       3309
//   ML-DSA-87       2592       4896       4627

func handleKeyGen(req *Request) Response {
	// FIPS 204 §6.1, Algorithm 6: ML-DSA.KeyGen_internal(ξ)
	//
	// Input "seed": 32 bytes (ξ, the key-generation seed).
	// Param "param_set": 44, 65, or 87.
	// Output "pk": public key bytes, "sk": secret key bytes.
	//
	// This MUST be deterministic: the same ξ must always produce the
	// same (pk, sk) pair, exactly matching Algorithm 6 of the spec.

	seed, err := getBytes(req, "seed")
	if err != nil {
		return errResp(err.Error())
	}
	paramSet, ok := getParam(req, "param_set")
	if !ok {
		return errResp("missing param 'param_set'")
	}
	if len(seed) != 32 {
		return errResp(fmt.Sprintf("seed must be 32 bytes, got %d", len(seed)))
	}

	// TODO: Call your ML-DSA KeyGen_internal with the given seed and parameter set.
	// switch paramSet {
	// case 44: pk, sk = yourMLDSA44KeyGenInternal(seed)
	// case 65: pk, sk = yourMLDSA65KeyGenInternal(seed)
	// case 87: pk, sk = yourMLDSA87KeyGenInternal(seed)
	// }
	_ = paramSet
	panic("TODO: implement ML_DSA_KeyGen")

	// return okResp(map[string]string{
	// 	"pk": hex.EncodeToString(pk),
	// 	"sk": hex.EncodeToString(sk),
	// })
}

func handleSign(req *Request) Response {
	// FIPS 204 §6.2, Algorithm 7: ML-DSA.Sign_internal(sk, M', rnd)
	//
	// Input "sk": secret key bytes (as returned by KeyGen).
	// Input "message": the formatted message M' (byte string).
	//   IMPORTANT: This is M', NOT the raw application message M.
	//   Pass these bytes directly to your Sign_internal. Do NOT apply
	//   any additional domain-separation encoding.
	// Input "rnd": 32 bytes.
	//   - Deterministic signing: rnd = {0}^32 (32 zero bytes).
	//   - Hedged signing: rnd = 32 fresh random bytes.
	// Param "param_set": 44, 65, or 87 (always provided by Crucible).
	// Output "signature": the encoded signature σ (byte string).

	sk, err := getBytes(req, "sk")
	if err != nil {
		return errResp(err.Error())
	}
	message, err := getBytes(req, "message")
	if err != nil {
		return errResp(err.Error())
	}
	rnd, err := getBytes(req, "rnd")
	if err != nil {
		return errResp(err.Error())
	}
	if len(rnd) != 32 {
		return errResp(fmt.Sprintf("rnd must be 32 bytes, got %d", len(rnd)))
	}

	// TODO: Call your ML-DSA Sign_internal.
	// signature := yourMLDSASignInternal(sk, message, rnd)
	_ = sk
	_ = message
	_ = rnd
	panic("TODO: implement ML_DSA_Sign")

	// return okResp(map[string]string{
	// 	"signature": hex.EncodeToString(signature),
	// })
}

func handleVerify(req *Request) Response {
	// FIPS 204 §6.3, Algorithm 8: ML-DSA.Verify_internal(pk, M', σ)
	//
	// Input "pk": public key bytes.
	// Input "message": the formatted message M' (byte string).
	//   IMPORTANT: Same as for Sign — this is M', not the raw message.
	// Input "sigma": the signature σ (byte string).
	// Param "param_set": 44, 65, or 87 (always provided by Crucible).
	// Output "valid": single byte — 0x01 if valid, 0x00 if invalid.
	//
	// Per FIPS 204 §3.6.2: implementations that accept pk or σ of
	// non-standard length SHALL return false (not an error).
	// Return "valid" = "00" for any malformed input, wrong-length
	// keys/signatures, or invalid signatures — do NOT return an error
	// response, as the battery tests expect a boolean result.

	pk, err := getBytes(req, "pk")
	if err != nil {
		return errResp(err.Error())
	}
	message, err := getBytes(req, "message")
	if err != nil {
		return errResp(err.Error())
	}
	sigma, err := getBytes(req, "sigma")
	if err != nil {
		return errResp(err.Error())
	}

	// TODO: Call your ML-DSA Verify_internal.
	// valid := yourMLDSAVerifyInternal(pk, message, sigma)
	_ = pk
	_ = message
	_ = sigma
	panic("TODO: implement ML_DSA_Verify")

	// validByte := byte(0x00)
	// if valid {
	// 	validByte = 0x01
	// }
	// return okResp(map[string]string{
	// 	"valid": hex.EncodeToString([]byte{validByte}),
	// })
}
