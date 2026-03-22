package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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

	enc.Encode(Handshake{
		Implementation: "circl-v1.6.3",
		Functions: []string{
			"ML_KEM_KeyGen",
			"ML_KEM_Encaps",
			"ML_KEM_Decaps",
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
	case "ML_KEM_KeyGen":
		return handleKEMKeyGen(req)
	case "ML_KEM_Encaps":
		return handleKEMEncaps(req)
	case "ML_KEM_Decaps":
		return handleKEMDecaps(req)
	case "ML_DSA_KeyGen":
		return handleDSAKeyGen(req)
	case "ML_DSA_Sign":
		return handleDSASign(req)
	case "ML_DSA_Verify":
		return handleDSAVerify(req)
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

// ---- ML-KEM ----

func handleKEMKeyGen(req *Request) Response {
	randomness, err := getBytes(req, "randomness")
	if err != nil {
		return errResp(err.Error())
	}
	if len(randomness) != 64 {
		return errResp(fmt.Sprintf("randomness must be 64 bytes, got %d", len(randomness)))
	}

	paramSet, _ := getParam(req, "param_set")

	switch paramSet {
	case 512:
		pk, sk := mlkem512.NewKeyFromSeed(randomness)
		ekBytes, _ := pk.MarshalBinary()
		dkBytes, _ := sk.MarshalBinary()
		return okResp(map[string]string{
			"ek": hex.EncodeToString(ekBytes),
			"dk": hex.EncodeToString(dkBytes),
		})
	case 768:
		pk, sk := mlkem768.NewKeyFromSeed(randomness)
		ekBytes, _ := pk.MarshalBinary()
		dkBytes, _ := sk.MarshalBinary()
		return okResp(map[string]string{
			"ek": hex.EncodeToString(ekBytes),
			"dk": hex.EncodeToString(dkBytes),
		})
	case 1024:
		pk, sk := mlkem1024.NewKeyFromSeed(randomness)
		ekBytes, _ := pk.MarshalBinary()
		dkBytes, _ := sk.MarshalBinary()
		return okResp(map[string]string{
			"ek": hex.EncodeToString(ekBytes),
			"dk": hex.EncodeToString(dkBytes),
		})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}

func handleKEMEncaps(req *Request) Response {
	ekBytes, err := getBytes(req, "ek")
	if err != nil {
		return errResp(err.Error())
	}
	randomness, err := getBytes(req, "randomness")
	if err != nil {
		return errResp(err.Error())
	}
	if len(randomness) != 32 {
		return errResp(fmt.Sprintf("randomness must be 32 bytes, got %d", len(randomness)))
	}

	// Determine param set from ek length.
	switch len(ekBytes) {
	case mlkem512.PublicKeySize:
		var pk mlkem512.PublicKey
		if err := pk.Unpack(ekBytes); err != nil {
			return errResp(fmt.Sprintf("invalid ek: %v", err))
		}
		ct := make([]byte, mlkem512.CiphertextSize)
		ss := make([]byte, mlkem512.SharedKeySize)
		pk.EncapsulateTo(ct, ss, randomness)
		return okResp(map[string]string{
			"c": hex.EncodeToString(ct),
			"K": hex.EncodeToString(ss),
		})
	case mlkem768.PublicKeySize:
		var pk mlkem768.PublicKey
		if err := pk.Unpack(ekBytes); err != nil {
			return errResp(fmt.Sprintf("invalid ek: %v", err))
		}
		ct := make([]byte, mlkem768.CiphertextSize)
		ss := make([]byte, mlkem768.SharedKeySize)
		pk.EncapsulateTo(ct, ss, randomness)
		return okResp(map[string]string{
			"c": hex.EncodeToString(ct),
			"K": hex.EncodeToString(ss),
		})
	case mlkem1024.PublicKeySize:
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(ekBytes); err != nil {
			return errResp(fmt.Sprintf("invalid ek: %v", err))
		}
		ct := make([]byte, mlkem1024.CiphertextSize)
		ss := make([]byte, mlkem1024.SharedKeySize)
		pk.EncapsulateTo(ct, ss, randomness)
		return okResp(map[string]string{
			"c": hex.EncodeToString(ct),
			"K": hex.EncodeToString(ss),
		})
	default:
		return errResp(fmt.Sprintf("invalid ek length: %d", len(ekBytes)))
	}
}

func handleKEMDecaps(req *Request) Response {
	ctBytes, err := getBytes(req, "c")
	if err != nil {
		return errResp(err.Error())
	}
	dkBytes, err := getBytes(req, "dk")
	if err != nil {
		return errResp(err.Error())
	}

	// Determine param set from dk length.
	switch len(dkBytes) {
	case mlkem512.PrivateKeySize:
		var sk mlkem512.PrivateKey
		if err := sk.Unpack(dkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid dk: %v", err))
		}
		if len(ctBytes) != mlkem512.CiphertextSize {
			return errResp(fmt.Sprintf("invalid ciphertext length for 512: %d", len(ctBytes)))
		}
		ss := make([]byte, mlkem512.SharedKeySize)
		sk.DecapsulateTo(ss, ctBytes)
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss),
		})
	case mlkem768.PrivateKeySize:
		var sk mlkem768.PrivateKey
		if err := sk.Unpack(dkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid dk: %v", err))
		}
		if len(ctBytes) != mlkem768.CiphertextSize {
			return errResp(fmt.Sprintf("invalid ciphertext length for 768: %d", len(ctBytes)))
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		sk.DecapsulateTo(ss, ctBytes)
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss),
		})
	case mlkem1024.PrivateKeySize:
		var sk mlkem1024.PrivateKey
		if err := sk.Unpack(dkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid dk: %v", err))
		}
		if len(ctBytes) != mlkem1024.CiphertextSize {
			return errResp(fmt.Sprintf("invalid ciphertext length for 1024: %d", len(ctBytes)))
		}
		ss := make([]byte, mlkem1024.SharedKeySize)
		sk.DecapsulateTo(ss, ctBytes)
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss),
		})
	default:
		return errResp(fmt.Sprintf("invalid dk length: %d", len(dkBytes)))
	}
}

// ---- ML-DSA ----

func handleDSAKeyGen(req *Request) Response {
	seed, err := getBytes(req, "seed")
	if err != nil {
		return errResp(err.Error())
	}
	if len(seed) != 32 {
		return errResp(fmt.Sprintf("seed must be 32 bytes, got %d", len(seed)))
	}

	paramSet, _ := getParam(req, "param_set")

	switch paramSet {
	case 44:
		var s [mldsa44.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa44.NewKeyFromSeed(&s)
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.Bytes()),
		})
	case 65:
		var s [mldsa65.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa65.NewKeyFromSeed(&s)
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.Bytes()),
		})
	case 87:
		var s [mldsa87.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa87.NewKeyFromSeed(&s)
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.Bytes()),
		})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}

func handleDSASign(req *Request) Response {
	skBytes, err := getBytes(req, "sk")
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

	paramSet, _ := getParam(req, "param_set")
	if paramSet == 0 {
		switch len(skBytes) {
		case mldsa44.PrivateKeySize:
			paramSet = 44
		case mldsa65.PrivateKeySize:
			paramSet = 65
		case mldsa87.PrivateKeySize:
			paramSet = 87
		}
	}

	var rndArr [32]byte
	copy(rndArr[:], rnd)

	// Use go:linkname-accessed internal SignTo to pass custom rnd.
	// The internal SignTo takes msg as func(io.Writer) and represents
	// ML-DSA.Sign_internal. We construct M' = 0 || 0 || msg (empty ctx).
	switch paramSet {
	case 44:
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig := make([]byte, mldsa44.SignatureSize)
		circlSignTo44(&sk, message, rndArr, sig)
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	case 65:
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig := make([]byte, mldsa65.SignatureSize)
		circlSignTo65(&sk, message, rndArr, sig)
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	case 87:
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig := make([]byte, mldsa87.SignatureSize)
		circlSignTo87(&sk, message, rndArr, sig)
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}

func handleDSAVerify(req *Request) Response {
	pkBytes, err := getBytes(req, "pk")
	if err != nil {
		return errResp(err.Error())
	}
	message, err := getBytes(req, "message")
	if err != nil {
		return errResp(err.Error())
	}
	sigBytes, err := getBytes(req, "sigma")
	if err != nil {
		return errResp(err.Error())
	}

	paramSet, _ := getParam(req, "param_set")
	if paramSet == 0 {
		switch len(pkBytes) {
		case mldsa44.PublicKeySize:
			paramSet = 44
		case mldsa65.PublicKeySize:
			paramSet = 65
		case mldsa87.PublicKeySize:
			paramSet = 87
		}
	}

	switch paramSet {
	case 44:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := mldsa44.Verify(&pk, message, nil, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	case 65:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := mldsa65.Verify(&pk, message, nil, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	case 87:
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := mldsa87.Verify(&pk, message, nil, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}
