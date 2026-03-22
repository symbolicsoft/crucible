package main

import (
	"bufio"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
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

	enc.Encode(Handshake{
		Implementation: "go-stdlib-mlkem",
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
	case "ML_DSA_KeyGen", "ML_DSA_Sign", "ML_DSA_Verify":
		// Go stdlib does not have crypto/mldsa yet.
		return Response{Unsupported: true}
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

// The Go stdlib crypto/mlkem supports ML-KEM-768 and ML-KEM-1024 only (no 512).
// NewDecapsulationKey768/1024 accepts a 64-byte seed in "d || z" form.
// Encapsulation is randomized by default; mlkemtest provides deterministic encaps.

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
		return errResp("ML-KEM-512 not supported by Go stdlib crypto/mlkem")
	case 768:
		dk, err := mlkem.NewDecapsulationKey768(randomness)
		if err != nil {
			return errResp(fmt.Sprintf("NewDecapsulationKey768: %v", err))
		}
		ek := dk.EncapsulationKey()
		return okResp(map[string]string{
			"ek": hex.EncodeToString(ek.Bytes()),
			"dk": hex.EncodeToString(dk.Bytes()),
		})
	case 1024:
		dk, err := mlkem.NewDecapsulationKey1024(randomness)
		if err != nil {
			return errResp(fmt.Sprintf("NewDecapsulationKey1024: %v", err))
		}
		ek := dk.EncapsulationKey()
		return okResp(map[string]string{
			"ek": hex.EncodeToString(ek.Bytes()),
			"dk": hex.EncodeToString(dk.Bytes()),
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
	// ML-KEM-768 ek = 1184 bytes, ML-KEM-1024 ek = 1568 bytes.
	switch len(ekBytes) {
	case 1184: // ML-KEM-768
		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid ek: %v", err))
		}
		ss, ct, err := mlkemtest.Encapsulate768(ek, randomness)
		if err != nil {
			return errResp(fmt.Sprintf("Encapsulate768: %v", err))
		}
		return okResp(map[string]string{
			"c": hex.EncodeToString(ct),
			"K": hex.EncodeToString(ss),
		})
	case 1568: // ML-KEM-1024
		ek, err := mlkem.NewEncapsulationKey1024(ekBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid ek: %v", err))
		}
		ss, ct, err := mlkemtest.Encapsulate1024(ek, randomness)
		if err != nil {
			return errResp(fmt.Sprintf("Encapsulate1024: %v", err))
		}
		return okResp(map[string]string{
			"c": hex.EncodeToString(ct),
			"K": hex.EncodeToString(ss),
		})
	case 800: // ML-KEM-512
		return errResp("ML-KEM-512 not supported by Go stdlib crypto/mlkem")
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

	// The Go stdlib dk.Bytes() returns the 64-byte seed, not the full expanded key.
	// NewDecapsulationKey768/1024 accepts this seed to reconstruct the key.
	switch len(dkBytes) {
	case 64:
		// Could be either 768 or 1024 — infer from ciphertext length.
		switch len(ctBytes) {
		case 1088: // ML-KEM-768 ct
			dk, err := mlkem.NewDecapsulationKey768(dkBytes)
			if err != nil {
				return errResp(fmt.Sprintf("NewDecapsulationKey768: %v", err))
			}
			ss, err := dk.Decapsulate(ctBytes)
			if err != nil {
				return errResp(fmt.Sprintf("Decapsulate: %v", err))
			}
			return okResp(map[string]string{
				"K": hex.EncodeToString(ss),
			})
		case 1568: // ML-KEM-1024 ct
			dk, err := mlkem.NewDecapsulationKey1024(dkBytes)
			if err != nil {
				return errResp(fmt.Sprintf("NewDecapsulationKey1024: %v", err))
			}
			ss, err := dk.Decapsulate(ctBytes)
			if err != nil {
				return errResp(fmt.Sprintf("Decapsulate: %v", err))
			}
			return okResp(map[string]string{
				"K": hex.EncodeToString(ss),
			})
		default:
			return errResp(fmt.Sprintf("cannot infer param_set from ct length %d with 64-byte dk seed", len(ctBytes)))
		}
	default:
		return errResp(fmt.Sprintf("invalid dk length: %d (Go stdlib uses 64-byte seed)", len(dkBytes)))
	}
}
